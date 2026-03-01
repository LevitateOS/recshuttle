use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallLayout {
    MutableSingleRoot,
    ImmutableAb,
}

#[derive(Debug, Clone)]
pub struct InstallPlanSpec {
    pub distro_id: String,
    pub os_name: String,
    pub default_hostname: String,
    pub default_password: String,
    pub install_bootloader_cmd: String,
    pub enable_serial_getty_cmd: String,
    pub include_initramfs: bool,
}

#[derive(Debug, Clone)]
pub struct SshExecOutput {
    pub exit_code: i32,
    pub output: String,
}

pub fn ssh_private_key_path() -> PathBuf {
    if let Ok(path) = std::env::var("LEVITATE_SSH_PRIVATE_KEY") {
        return PathBuf::from(path);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".ssh/id_ed25519");
    }
    PathBuf::from("/root/.ssh/id_ed25519")
}

pub fn ssh_exec(ssh_host_port: u16, key_path: &Path, remote_cmd: &str) -> Result<SshExecOutput> {
    if !key_path.is_file() {
        bail!(
            "SSH private key not found at '{}'. Set LEVITATE_SSH_PRIVATE_KEY to a readable key.",
            key_path.display()
        );
    }

    let output = Command::new("ssh")
        .args([
            "-i",
            &key_path.to_string_lossy(),
            "-p",
            &ssh_host_port.to_string(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "root@127.0.0.1",
            remote_cmd,
        ])
        .output()
        .with_context(|| {
            format!(
                "running host SSH command against forwarded live SSH port {}",
                ssh_host_port
            )
        })?;

    let mut merged = String::new();
    merged.push_str(&String::from_utf8_lossy(&output.stdout));
    merged.push_str(&String::from_utf8_lossy(&output.stderr));

    Ok(SshExecOutput {
        exit_code: output.status.code().unwrap_or(255),
        output: merged,
    })
}

pub fn ssh_exec_default_key(ssh_host_port: u16, remote_cmd: &str) -> Result<SshExecOutput> {
    let key_path = ssh_private_key_path();
    ssh_exec(ssh_host_port, &key_path, remote_cmd)
}

pub struct RemoteInstallerService {
    ssh_host_port: u16,
    key_path: PathBuf,
}

impl RemoteInstallerService {
    pub fn new(ssh_host_port: u16) -> Self {
        Self {
            ssh_host_port,
            key_path: ssh_private_key_path(),
        }
    }

    pub fn with_key_path(ssh_host_port: u16, key_path: PathBuf) -> Self {
        Self {
            ssh_host_port,
            key_path,
        }
    }

    pub fn exec(&self, remote_cmd: &str) -> Result<SshExecOutput> {
        ssh_exec(self.ssh_host_port, &self.key_path, remote_cmd)
    }

    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let started = Instant::now();
        let mut last_err = String::new();
        while started.elapsed() < timeout {
            match self.exec("echo __REMOTE_INSTALLER_READY__") {
                Ok(result)
                    if result.exit_code == 0
                        && result.output.contains("__REMOTE_INSTALLER_READY__") =>
                {
                    return Ok(());
                }
                Ok(result) => {
                    last_err = result.output;
                }
                Err(err) => {
                    last_err = format!("{err:#}");
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        bail!(
            "remote installer service did not become ready on forwarded SSH port {} within {}s.\nLast error:\n{}",
            self.ssh_host_port,
            timeout.as_secs(),
            last_err
        );
    }

    pub fn run_install_plan(&self, steps: &[(&str, String)]) -> Result<usize> {
        let mut executed = 0usize;
        for (desc, cmd) in steps {
            println!("    -> {}", desc);
            let result = self.exec(cmd).with_context(|| {
                format!(
                    "running remote installer step '{}' via SSH port {}",
                    desc, self.ssh_host_port
                )
            })?;
            if result.exit_code != 0 {
                bail!(
                    "remote installer step '{}' failed (exit {}): {}",
                    desc,
                    result.exit_code,
                    result.output.trim()
                );
            }
            executed += 1;
        }
        Ok(executed)
    }

    pub fn resolve_install_disk(&self) -> Result<String> {
        let probe = r#"for dev in /dev/vda /dev/vdb /dev/sda /dev/sdb /dev/nvme0n1 /dev/mmcblk0; do
    [ -b "$dev" ] || continue
    name="${dev##*/}"
    ro="$(cat "/sys/class/block/$name/ro" 2>/dev/null || echo 1)"
    [ "$ro" = "0" ] || continue
    case "$name" in
        sr*|loop*|ram*) continue ;;
    esac
    printf '%s\n' "$dev"
    exit 0
done
exit 1"#;
        let result = self.exec(probe).with_context(|| {
            format!(
                "probing writable install disk via SSH port {}",
                self.ssh_host_port
            )
        })?;
        if result.exit_code != 0 {
            bail!(
                "could not locate writable install disk in remote installer VM (exit {}): {}",
                result.exit_code,
                result.output.trim()
            );
        }
        let disk = result
            .output
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("/dev/"))
            .unwrap_or("")
            .to_string();
        if disk.is_empty() {
            bail!(
                "remote installer disk probe returned no device path: {}",
                result.output.trim()
            );
        }
        Ok(disk)
    }

    pub fn verify_checks(&self, checks: &[(&str, String)]) -> Result<()> {
        for (desc, cmd) in checks {
            let result = self.exec(cmd).with_context(|| {
                format!(
                    "running remote installer verification '{}' via SSH port {}",
                    desc, self.ssh_host_port
                )
            })?;
            if result.exit_code != 0 {
                bail!(
                    "remote installer verification '{}' failed (exit {}): {}",
                    desc,
                    result.exit_code,
                    result.output.trim()
                );
            }
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        let result = self.exec("poweroff -f").with_context(|| {
            format!(
                "requesting remote installer VM shutdown via SSH port {}",
                self.ssh_host_port
            )
        })?;
        if result.exit_code == 0 {
            return Ok(());
        }

        // Poweroff often severs SSH before clean command completion; tolerate disconnect-style exits.
        let output = result.output.to_lowercase();
        if output.contains("connection")
            || output.contains("closed")
            || output.contains("reset by peer")
            || output.contains("broken pipe")
        {
            return Ok(());
        }

        bail!(
            "remote installer shutdown failed (exit {}): {}",
            result.exit_code,
            result.output.trim()
        )
    }
}

pub fn runtime_policy_checks_for_install(
    distro_id: &str,
    install_layout: InstallLayout,
    install_disk: &str,
) -> Vec<(&'static str, String)> {
    if install_layout != InstallLayout::ImmutableAb {
        return Vec::new();
    }

    let root_a_part = partition_path(install_disk, 2);
    let root_b_part = partition_path(install_disk, 3);
    let var_part = partition_path(install_disk, 4);
    let entry_a = format!("/mnt/sysroot/boot/loader/entries/{}-a.conf", distro_id);
    let entry_b = format!("/mnt/sysroot/boot/loader/entries/{}-b.conf", distro_id);

    vec![
        (
            "Runtime policy: root mount is read-only",
            "awk '$2==\"/\" && $4 ~ /(^|,)ro(,|$)/ {ok=1} END{exit(ok?0:1)}' /mnt/sysroot/etc/fstab".to_string(),
        ),
        (
            "Runtime policy: /var mount is present",
            "awk '$2==\"/var\" {ok=1} END{exit(ok?0:1)}' /mnt/sysroot/etc/fstab".to_string(),
        ),
        (
            "Runtime policy: system-a label",
            format!("test \"$(blkid -s LABEL -o value {root_a_part})\" = \"system-a\""),
        ),
        (
            "Runtime policy: system-b label",
            format!("test \"$(blkid -s LABEL -o value {root_b_part})\" = \"system-b\""),
        ),
        (
            "Runtime policy: var label",
            format!("test \"$(blkid -s LABEL -o value {var_part})\" = \"var\""),
        ),
        (
            "Runtime policy: loader default slot",
            format!("grep -q '^default {}-a.conf$' /mnt/sysroot/boot/loader/loader.conf", distro_id),
        ),
        (
            "Runtime policy: slot A entry root label",
            format!("grep -q 'root=LABEL=system-a' {entry_a}"),
        ),
        (
            "Runtime policy: slot B entry root label",
            format!("grep -q 'root=LABEL=system-b' {entry_b}"),
        ),
    ]
}

pub fn install_commands_for(
    spec: &InstallPlanSpec,
    install_disk: &str,
    install_layout: InstallLayout,
) -> Vec<(&'static str, String)> {
    let efi_part = partition_path(install_disk, 1);

    let mut install_cmds = match install_layout {
        InstallLayout::MutableSingleRoot => {
            let root_part = partition_path(install_disk, 2);
            let boot_entry_path = format!(
                "/mnt/sysroot/boot/loader/entries/{}.conf",
                spec.distro_id.as_str()
            );
            let loader_conf_cmd = format!(
                "mkdir -p /mnt/sysroot/boot/loader/entries && \
                 printf '%s\\n' 'default {}.conf' 'timeout 5' 'editor 0' 'console-mode max' > /mnt/sysroot/boot/loader/loader.conf",
                spec.distro_id.as_str()
            );
            let boot_entry_cmd = if spec.include_initramfs {
                format!(
                    "ROOT_UUID=$(blkid -s UUID -o value {root_part}) && [ -n \"$ROOT_UUID\" ] && \
                     printf '%s\\n' 'title {title}' 'linux /vmlinuz' 'initrd /initramfs.img' \
                     \"options root=UUID=$ROOT_UUID rw rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    root_part = root_part.as_str(),
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_path
                )
            } else {
                format!(
                    "ROOT_PARTUUID=$(blkid -s PARTUUID -o value {root_part}) && [ -n \"$ROOT_PARTUUID\" ] && \
                     printf '%s\\n' 'title {title}' 'linux /vmlinuz' \
                     \"options root=PARTUUID=$ROOT_PARTUUID rw rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    root_part = root_part.as_str(),
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_path
                )
            };

            vec![
                (
                    "Partition disk",
                    format!(
                        "echo 'label: gpt\nsize=512M, type=uefi\ntype=linux' | sfdisk {}",
                        install_disk
                    ),
                ),
                (
                    "Format EFI partition",
                    format!("mkfs.fat -F32 {}", efi_part),
                ),
                (
                    "Format root partition",
                    format!("mkfs.ext4 -F {}", root_part),
                ),
                (
                    "Mount root",
                    format!("mkdir -p /mnt/sysroot && mount {} /mnt/sysroot", root_part),
                ),
                (
                    "Mount boot",
                    format!(
                        "mkdir -p /mnt/sysroot/boot && mount {} /mnt/sysroot/boot",
                        efi_part
                    ),
                ),
                (
                    "Copy kernel",
                    "cp /run/live-media/boot/vmlinuz /mnt/sysroot/boot/vmlinuz".to_string(),
                ),
                (
                    "Extract rootfs",
                    "recstrap --force /mnt/sysroot".to_string(),
                ),
                ("Generate fstab", "recfstab /mnt/sysroot".to_string()),
                (
                    "Install bootloader",
                    format!(
                        "recchroot /mnt/sysroot -- {}",
                        spec.install_bootloader_cmd.as_str()
                    ),
                ),
                ("Write loader config", loader_conf_cmd),
                ("Write boot entry", boot_entry_cmd),
                (
                    "Set hostname",
                    format!(
                        "echo {} > /mnt/sysroot/etc/hostname",
                        spec.default_hostname.as_str()
                    ),
                ),
                (
                    "Set root password",
                    format!(
                        "recchroot /mnt/sysroot -- sh -c 'echo root:{} | chpasswd'",
                        spec.default_password.as_str()
                    ),
                ),
                (
                    "Enable serial getty",
                    format!(
                        "recchroot /mnt/sysroot -- sh -c '{}'",
                        spec.enable_serial_getty_cmd.as_str()
                    ),
                ),
            ]
        }
        InstallLayout::ImmutableAb => {
            let root_a_part = partition_path(install_disk, 2);
            let root_b_part = partition_path(install_disk, 3);
            let var_part = partition_path(install_disk, 4);

            let boot_entry_a_path = format!(
                "/mnt/sysroot/boot/loader/entries/{}-a.conf",
                spec.distro_id.as_str()
            );
            let boot_entry_b_path = format!(
                "/mnt/sysroot/boot/loader/entries/{}-b.conf",
                spec.distro_id.as_str()
            );
            let loader_conf_cmd = format!(
                "mkdir -p /mnt/sysroot/boot/loader/entries && \
                 printf '%s\\n' 'default {}-a.conf' 'timeout 5' 'editor 0' 'console-mode max' > /mnt/sysroot/boot/loader/loader.conf",
                spec.distro_id.as_str()
            );

            let boot_entry_a_cmd = if spec.include_initramfs {
                format!(
                    "printf '%s\\n' 'title {title} (Slot A)' 'linux /vmlinuz' 'initrd /initramfs.img' \
                     \"options root=LABEL=system-a ro rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_a_path
                )
            } else {
                format!(
                    "printf '%s\\n' 'title {title} (Slot A)' 'linux /vmlinuz' \
                     \"options root=LABEL=system-a ro rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_a_path
                )
            };
            let boot_entry_b_cmd = if spec.include_initramfs {
                format!(
                    "printf '%s\\n' 'title {title} (Slot B)' 'linux /vmlinuz' 'initrd /initramfs.img' \
                     \"options root=LABEL=system-b ro rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_b_path
                )
            } else {
                format!(
                    "printf '%s\\n' 'title {title} (Slot B)' 'linux /vmlinuz' \
                     \"options root=LABEL=system-b ro rootwait console=tty0 console=ttyS0,115200n8\" > {entry_path}",
                    title = spec.os_name.as_str(),
                    entry_path = boot_entry_b_path
                )
            };

            vec![
                (
                    "Partition disk (A/B + var)",
                    format!(
                        "echo 'label: gpt\nsize=512M, type=uefi\nsize=6G, type=linux\nsize=6G, type=linux\ntype=linux' | sfdisk {}",
                        install_disk
                    ),
                ),
                (
                    "Format EFI partition",
                    format!("mkfs.fat -F32 -n EFI {}", efi_part),
                ),
                (
                    "Format slot A root partition",
                    format!("mkfs.ext4 -F -L system-a {}", root_a_part),
                ),
                (
                    "Format slot B root partition",
                    format!("mkfs.ext4 -F -L system-b {}", root_b_part),
                ),
                (
                    "Format persistent var partition",
                    format!("mkfs.ext4 -F -L var {}", var_part),
                ),
                (
                    "Mount slot A root",
                    format!("mkdir -p /mnt/sysroot && mount {} /mnt/sysroot", root_a_part),
                ),
                (
                    "Mount boot",
                    format!(
                        "mkdir -p /mnt/sysroot/boot && mount {} /mnt/sysroot/boot",
                        efi_part
                    ),
                ),
                (
                    "Mount persistent var",
                    format!("mkdir -p /mnt/sysroot/var && mount {} /mnt/sysroot/var", var_part),
                ),
                (
                    "Copy kernel",
                    "cp /run/live-media/boot/vmlinuz /mnt/sysroot/boot/vmlinuz".to_string(),
                ),
                (
                    "Extract rootfs",
                    "recstrap --force /mnt/sysroot".to_string(),
                ),
                ("Generate fstab", "recfstab /mnt/sysroot".to_string()),
                (
                    "Enforce immutable root mount",
                    format!(
                        "ROOT_UUID=$(blkid -s UUID -o value {root_a_part}) && \
                         EFI_UUID=$(blkid -s UUID -o value {efi_part}) && \
                         VAR_UUID=$(blkid -s UUID -o value {var_part}) && \
                         [ -n \"$ROOT_UUID\" ] && [ -n \"$EFI_UUID\" ] && [ -n \"$VAR_UUID\" ] && \
                         printf 'UUID=%s / ext4 ro 0 1\\nUUID=%s /boot vfat defaults 0 2\\nUUID=%s /var ext4 defaults 0 2\\n' \"$ROOT_UUID\" \"$EFI_UUID\" \"$VAR_UUID\" > /mnt/sysroot/etc/fstab",
                        root_a_part = root_a_part.as_str(),
                        efi_part = efi_part.as_str(),
                        var_part = var_part.as_str()
                    ),
                ),
                (
                    "Install bootloader",
                    format!(
                        "recchroot /mnt/sysroot -- {}",
                        spec.install_bootloader_cmd.as_str()
                    ),
                ),
                ("Write loader config", loader_conf_cmd),
                ("Write slot A boot entry", boot_entry_a_cmd),
                ("Write slot B boot entry", boot_entry_b_cmd),
                (
                    "Set hostname",
                    format!(
                        "echo {} > /mnt/sysroot/etc/hostname",
                        spec.default_hostname.as_str()
                    ),
                ),
                (
                    "Set root password",
                    format!(
                        "recchroot /mnt/sysroot -- sh -c 'echo root:{} | chpasswd'",
                        spec.default_password.as_str()
                    ),
                ),
                (
                    "Enable serial getty",
                    format!(
                        "recchroot /mnt/sysroot -- sh -c '{}'",
                        spec.enable_serial_getty_cmd.as_str()
                    ),
                ),
            ]
        }
    };

    if spec.include_initramfs {
        install_cmds.insert(
            6,
            (
                "Copy initramfs",
                "cp /run/live-media/boot/initramfs.img /mnt/sysroot/boot/initramfs.img".to_string(),
            ),
        );
    }

    install_cmds
}

fn partition_path(disk: &str, index: u8) -> String {
    if disk.starts_with("/dev/nvme") || disk.starts_with("/dev/mmcblk") {
        return format!("{disk}p{index}");
    }
    format!("{disk}{index}")
}
