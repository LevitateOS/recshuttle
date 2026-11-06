//! SSH transport to a QEMU guest whose SSH port is forwarded to the host.
//!
//! This crate only moves commands and output; what to run is the caller's.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use recqemu::HOSTFWD_ADDRESS;

#[derive(Debug, Clone)]
pub struct SshExecOutput {
    /// 255 when ssh itself failed (as ssh reports it) or no status was given.
    pub exit_code: i32,
    /// stdout followed by stderr.
    pub output: String,
}

/// The private key for guest root logins: `LEVITATE_SSH_PRIVATE_KEY`, else
/// `~/.ssh/id_ed25519`.
pub fn ssh_private_key_path() -> PathBuf {
    if let Ok(path) = std::env::var("LEVITATE_SSH_PRIVATE_KEY") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".ssh/id_ed25519")
}

/// A guest reachable as root over a forwarded SSH port.
pub struct Remote {
    port: u16,
    key_path: PathBuf,
}

impl Remote {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            key_path: ssh_private_key_path(),
        }
    }

    /// Run `remote_cmd` in the guest's shell.
    pub fn exec(&self, remote_cmd: &str) -> Result<SshExecOutput> {
        if !self.key_path.is_file() {
            bail!(
                "SSH private key not found at '{}'. Set LEVITATE_SSH_PRIVATE_KEY to a readable key.",
                self.key_path.display()
            );
        }
        let output = Command::new("ssh")
            .arg("-i")
            .arg(&self.key_path)
            .args(["-p", &self.port.to_string()])
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "ConnectTimeout=5"])
            .arg(format!("root@{HOSTFWD_ADDRESS}"))
            .arg(remote_cmd)
            .output()
            .with_context(|| format!("running ssh against forwarded guest port {}", self.port))?;
        let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
        merged.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(SshExecOutput {
            exit_code: output.status.code().unwrap_or(255),
            output: merged,
        })
    }

    /// Run `remote_cmd` and return its output, failing unless it exits 0.
    /// `what` names the step in the error.
    pub fn run(&self, what: &str, remote_cmd: &str) -> Result<String> {
        let result = self
            .exec(remote_cmd)
            .with_context(|| format!("{what} (guest port {})", self.port))?;
        if result.exit_code != 0 {
            bail!(
                "{what} failed (exit {}): {}",
                result.exit_code,
                result.output.trim()
            );
        }
        Ok(result.output)
    }

    /// Wait until a root login runs commands.
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        const MARKER: &str = "__RECSHUTTLE_READY__";
        let started = Instant::now();
        let mut last_err = String::new();
        while started.elapsed() < timeout {
            match self.exec(&format!("echo {MARKER}")) {
                Ok(result) if result.exit_code == 0 && result.output.contains(MARKER) => {
                    return Ok(());
                }
                Ok(result) => last_err = result.output,
                Err(err) => last_err = format!("{err:#}"),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        bail!(
            "guest SSH on forwarded port {} did not accept a root login within {}s.\nLast error:\n{}",
            self.port,
            timeout.as_secs(),
            last_err
        );
    }

    /// Ask the guest to power off. The connection drops while it does, so
    /// there is no result to report.
    pub fn power_off(&self) {
        let _ = self.exec("poweroff -f");
    }
}
