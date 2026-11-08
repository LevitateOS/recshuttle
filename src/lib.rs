//! SSH transport to a QEMU guest whose SSH port is forwarded to the host,
//! and the login key the guests trust.
//!
//! This crate only moves commands and output; what to run is the caller's.
//! Every connection uses one configuration: the caller's key and user, no
//! `~/.ssh/config` (`-F /dev/null`), only that key (`IdentitiesOnly`), and a
//! known-hosts file of its own that goes when the [`Remote`] does.

use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use recqemu::HOSTFWD_ADDRESS;

#[derive(Debug, Clone)]
pub struct SshExecOutput {
    /// 255 when ssh itself failed (as ssh reports it) or no status was given.
    pub exit_code: i32,
    /// stdout followed by stderr.
    pub output: String,
}

/// Who logs in to a guest, and with which private key.
#[derive(Debug, Clone)]
pub struct Login {
    pub key: PathBuf,
    pub user: String,
}

/// The public half of `key`: `ssh-keygen` writes it as `<key>.pub`.
pub fn public_key_path(key: &Path) -> PathBuf {
    let mut path = OsString::from(key.as_os_str());
    path.push(".pub");
    PathBuf::from(path)
}

/// The private key at `key`, created with `ssh-keygen` (ed25519, no
/// passphrase) when it or its public half is missing.
pub fn ensure_key(key: &Path) -> Result<()> {
    let public = public_key_path(key);
    if key.is_file() && public.is_file() {
        return Ok(());
    }
    let dir = key
        .parent()
        .with_context(|| format!("'{}' has no parent directory", key.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for half in [key, public.as_path()] {
        match std::fs::remove_file(half) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(err).with_context(|| format!("removing the half key {}", half.display()))
            }
            _ => {}
        }
    }
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "scenario-guests", "-f"])
        .arg(key)
        .status()
        .context("running ssh-keygen (OpenSSH's client tools) to create the guest login key")?;
    if !status.success() {
        bail!("ssh-keygen failed creating {}", key.display());
    }
    eprintln!("[info] created the guest login key {}", key.display());
    Ok(())
}

/// The public key line of `key`, for a guest's `authorized_keys`.
pub fn public_key(key: &Path) -> Result<String> {
    let path = public_key_path(key);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the public key {}", path.display()))?;
    Ok(text.trim().to_string())
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A guest reachable over a forwarded SSH port.
pub struct Remote {
    port: u16,
    login: Login,
    /// This connection's known-hosts file, removed on drop.
    known_hosts: PathBuf,
}

impl Drop for Remote {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.known_hosts) {
            if err.kind() != std::io::ErrorKind::NotFound {
                eprintln!("warning: could not remove {}: {err}", self.known_hosts.display());
            }
        }
    }
}

impl Remote {
    pub fn new(port: u16, login: Login) -> Self {
        let known_hosts = std::env::temp_dir().join(format!(
            "scenario-ssh-known-hosts-{}-{}-{port}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            port,
            login,
            known_hosts,
        }
    }

    /// `ssh` with this guest's options and login, before the remote command.
    pub fn command(&self) -> Command {
        let mut ssh = Command::new("ssh");
        ssh.args(["-F", "/dev/null"])
            .arg("-i")
            .arg(&self.login.key)
            .args(["-p", &self.port.to_string()])
            .args(["-o", "IdentitiesOnly=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            // Keeps ssh's own notices out of command output (a command's JSON).
            .args(["-o", "LogLevel=ERROR"])
            .args(["-o", "ConnectTimeout=5"]);
        ssh
    }

    fn destination(&self) -> String {
        format!("{}@{HOSTFWD_ADDRESS}", self.login.user)
    }

    /// Run `remote_cmd` in the guest's shell.
    pub fn exec(&self, remote_cmd: &str) -> Result<SshExecOutput> {
        if !self.login.key.is_file() {
            bail!("SSH private key not found at '{}'", self.login.key.display());
        }
        let output = self
            .command()
            .args(["-o", "BatchMode=yes"])
            .arg(self.destination())
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

    /// Wait until a login runs commands.
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
            "guest SSH on forwarded port {} did not accept a login as {} within {}s.\nLast error:\n{}",
            self.port,
            self.login.user,
            timeout.as_secs(),
            last_err
        );
    }

    /// An interactive login session on this terminal; returns when it ends.
    pub fn interactive(&self) -> Result<()> {
        let status = self
            .command()
            .args(["-tt", "-o", "BatchMode=no"])
            .arg(self.destination())
            .env("TERM", "vt100")
            .status()
            .context("starting the interactive SSH session")?;
        if !status.success() {
            bail!("the interactive SSH session exited with {status}");
        }
        Ok(())
    }
}
