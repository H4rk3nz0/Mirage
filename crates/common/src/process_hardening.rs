//! Process-level hygiene for security-sensitive daemons.
//!
//! A Mirage bridge or client keeps live key material in memory: Noise
//! transport keys, ML-KEM shared secrets, ratchet roots, capability-token
//! bytes. `Zeroizing<T>` wrappers zero that material when `Drop` runs, but
//! two things happen _outside_ of Drop that can still leak it:
//!
//! 1. **Core dumps.** If the process faults, the kernel can write a
//!    post-mortem snapshot of its address space to disk. On Linux the
//!    default location (`/var/lib/systemd/coredump/`, `/cores/`, or
//!    `core` in the cwd) is typically world-readable to root and often
//!    persists across reboots. A core file captured at the moment of
//!    a panic contains every key that was live - exactly the moment an
//!    adversary is most likely to have seized the machine.

//! 2. **Crash reporters.** On Windows, Windows Error Reporting (WER) can
//!    upload a minidump to Microsoft and also persist a local copy under
//!    `%LOCALAPPDATA%\CrashDumps`.
//!
//! This module provides one entry point, [`harden_process`], that callers
//! (bridge `main()`, client `main()`) invoke as early as possible -
//! ideally before the first keypair is generated. It is idempotent and
//! does not require `unsafe` (the workspace forbids it).
//!
//! # Threat-model scope
//!
//! This is **defense in depth**, not a primary control. A sufficiently
//! privileged adversary on the host can:
//! - attach `ptrace` / `ReadProcessMemory` to the running process,
//! - read `/proc/<pid>/mem`,
//! - snapshot the VM from the hypervisor.
//!
//! None of those are stopped by disabling core dumps. The control stops
//! _passive_ post-mortem key exposure (forensic disk grabs, default
//! crash-reporter uploads). Pair it with:
//! - `mlock` on sensitive pages (out of scope for v0.1 - `mlock` requires
//!   raw syscalls or the `mlock` crate, which uses `unsafe` internally),
//! - kernel `kernel.core_pattern=|/bin/true` (operator-controlled),
//! - disk encryption at rest (e.g. LUKS, `BitLocker`).
//!
//! ## Residual exposure
//!
//! - **macOS `ReportCrash`.** `setrlimit(RLIMIT_CORE, 0)` suppresses
//!   Mach-O core files but does not prevent the userspace `ReportCrash`
//!   helper from writing `.ips` / `.crash` diagnostic reports under
//!   `~/Library/Logs/DiagnosticReports/`. Those reports include thread
//!   stacks (no heap) - register values at crash time may still expose
//!   a small amount of key material that was in-register. Operators
//!   running on macOS should additionally disable `ReportCrash` via
//!   `launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist`
//!   (policy choice, outside this library's scope).
//! - **Startup window.** A signal that arrives between `main()` entry
//!   and the first call to [`harden_process`] may still produce a core
//!   file. Callers MUST invoke this helper as the first statement of
//!   `main()` - before parsing config, before generating keypairs, and
//!   before spawning any thread. The window is intrinsically
//!   un-closable from userspace; supervisors can narrow it further by
//!   pre-setting `LimitCORE=0` (systemd) or `ulimit -c 0` (shell).

use std::io;

/// Result of [`harden_process`]. Carried through to logs for operator
/// visibility so operators can tell whether the process successfully
/// disabled core dumps at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// On POSIX: `RLIMIT_CORE` was successfully set to `(0, 0)`.
    /// On non-POSIX: always `false`.
    pub core_dumps_disabled: bool,
    /// True on targets where no meaningful hardening is possible from
    /// userspace without `unsafe` (currently: Windows). Operators on
    /// those platforms should rely on OS-level controls (WER policy,
    /// `BitLocker`, etc.).
    pub best_effort: bool,
}

/// Apply all process-level hardening. Idempotent.
///
/// On POSIX: sets `RLIMIT_CORE` to `(0, 0)` so the kernel does not write
/// core files. The per-process limit cannot be raised again by the
/// process itself unless it has `CAP_SYS_RESOURCE`; for an unprivileged
/// bridge this is effectively permanent for the lifetime of the process.
///
/// On non-POSIX (Windows, WASI): returns `Ok(HardenReport { ..,
/// best_effort: true })`. Windows WER is best configured via group
/// policy / `WerAddExcludedApplication`, which is outside the scope of
/// a safe, dependency-minimal helper.
/// # Errors
///
/// Returns the underlying [`io::Error`] if `setrlimit` fails. Callers
/// should treat a failure as a **startup error** and refuse to load key
/// material - shipping keys into a process that could dump them to disk
/// defeats the whole point.
pub fn harden_process() -> io::Result<HardenReport> {
    #[cfg(unix)]
    {
        disable_core_dumps_unix()?;
        Ok(HardenReport {
            core_dumps_disabled: true,
            best_effort: false,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(HardenReport {
            core_dumps_disabled: false,
            best_effort: true,
        })
    }
}

#[cfg(unix)]
fn disable_core_dumps_unix() -> io::Result<()> {
    // `rlimit` is a safe wrapper over `getrlimit(2)` / `setrlimit(2)`.
    // Both RLIM_CUR and RLIM_MAX are set to 0; lowering RLIM_MAX is
    // one-way for an unprivileged process, which is exactly what we
    // want - the process cannot undo this even if compromised later.
    rlimit::Resource::CORE.set(0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_is_idempotent() {
        // Running in a test harness, the limit may already be zero (or
        // not). Either way, two consecutive calls must both succeed.
        let r1 = harden_process().expect("first harden call");
        let r2 = harden_process().expect("second harden call");
        assert_eq!(r1, r2, "idempotent report");
    }

    #[cfg(unix)]
    #[test]
    fn core_limit_is_zero_after_harden() {
        harden_process().expect("harden");
        let (soft, hard) = rlimit::Resource::CORE.get().expect("getrlimit");
        assert_eq!(soft, 0, "soft RLIMIT_CORE must be 0");
        assert_eq!(hard, 0, "hard RLIMIT_CORE must be 0");
    }
}
