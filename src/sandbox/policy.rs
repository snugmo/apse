//! The nono capability set of a sandboxed run (PLAN.md Phase 4,
//! decisions #22–#25): the Landlock floor and the supervisor's
//! allowlist are both derived from this single `CapabilitySet`, so
//! they cannot disagree.
//!
//! Built identically in S and in B from the same pure function (B
//! re-runs it after the forks — the value itself is not shared).

use anyhow::{Context, Result, bail};
use nono::capability::{AccessMode, CapabilitySet, IpcMode, SignalMode, UnixSocketMode};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

use crate::sandbox::SandboxConfig;
use crate::sandbox::mounts;

/// Base grants every app needs, independent of its profile.
///
/// `/` is Read (refer/traverse): Landlock is a default-deny floor, so
/// without the ancestor grant the app could not even resolve the
/// granted subtrees (decision #24). The self-bind of `/` already
/// shows the app every top-level directory, so this adds no
/// visibility.
const BASE_READ: &[&str] = &[
    "/", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys",
];

/// The capability set for `config`: the base app grants plus the
/// profile's binds, sockets, network, signal and IPC modes.
///
/// `instance_dir` is the per-instance runtime dir's path **as the
/// app sees it inside the sandbox** (the fresh `/run`'s
/// systemd-standard location — `mounts::sandbox_instance_dir`). It
/// is that string the supervisor matches on (the app presents
/// sandbox-side paths to its trapped syscalls) and that the
/// Landlock floor binds in B; for the default XDG it equals the
/// host path, for a divergent XDG it does not (decision #28, the
/// Phase-5 path translation).
pub(crate) fn capability_set(config: &SandboxConfig, instance_dir: &Path) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();
    for p in BASE_READ {
        caps = caps
            .allow_path(*p, AccessMode::Read)
            .with_context(|| format!("granting read access to {p}"))?;
    }
    // The per-instance /etc files (task 8.10): `hosts`/`hostname`
    // are generated in A and bound over the self-bind-layer /etc.
    // Landlock matches **inodes**, and a single-file bind is not
    // *beneath* `/etc` in the dentry tree, so the `/etc` directory
    // grant above does not reach them — the rules must be on the
    // file inodes (`allow_file`, not `allow_path`). The same pure
    // function runs in S (where `/etc/hosts` is still the host's
    // real file — redundant but consistent) and in B, after the
    // build (where it is the scratch inode — the one the floor
    // enforces). Read-only: the app must not be able to mutate its
    // own identity (the confined-mode mirror is the module's
    // read-only `apse_etc_t` rule).
    for f in ["/etc/hosts", "/etc/hostname"] {
        caps = caps
            .allow_file(f, AccessMode::Read)
            .with_context(|| format!("granting read access to {f}"))?;
    }
    // The fresh /dev tmpfs holds only the nodes we bound (plus the
    // pts instance), so RW on it means exactly "the app's devices".
    caps = caps
        .allow_path("/dev", AccessMode::ReadWrite)
        .context("granting /dev")?;
    // /tmp is a fresh tmpfs (sized by the profile).
    caps = caps
        .allow_path("/tmp", AccessMode::ReadWrite)
        .context("granting /tmp")?;
    // The per-instance /run dir (the tagged Wayland socket's home —
    // Phase 5), and its socket subtree.
    caps = caps
        .allow_path(instance_dir, AccessMode::ReadWrite)
        .with_context(|| format!("granting the instance dir {instance_dir:?}"))?;
    caps = caps
        .allow_unix_socket_subtree(instance_dir, UnixSocketMode::Connect)
        .with_context(|| format!("granting the socket subtree of {instance_dir:?}"))?;
    // The app's home and XDG dirs (decision #43; the private
    // per-app home is the only mode since #44). The targets are
    // the *sandbox-side* strings (the app's env keeps them
    // unchanged); they resolve, in B's namespace, to the per-app
    // state tree bound over the standard locations, and one grant at
    // the home covers the XDG submounts beneath it (Landlock
    // matches the inode chain of the resolved path — a submount is
    // an extra step between the granted ancestor and the file). Only
    // existing targets are granted: a missing custom XDG dir is not
    // bind-mounted either (step 7), so granting it would be dead
    // weight (and a hard error, since `allow_path` needs a path).
    let home = std::env::var("HOME").context("HOME is required for the home grant")?;
    for b in mounts::home_xdg_targets(&home) {
        if !Path::new(&b.target).is_dir() {
            continue;
        }
        caps = caps
            .allow_path(&b.target, AccessMode::ReadWrite)
            .with_context(|| format!("granting the {} dir {} read+write", b.sub, b.target))?;
    }
    // Profile grants (a missing path is a hard error, like a bad
    // rootfs bind).
    for p in &config.profile.ro_binds {
        caps = caps
            .allow_path(p, AccessMode::Read)
            .with_context(|| format!("granting read access to the ro-bind {p}"))?;
    }
    for p in &config.profile.rw_binds {
        caps = caps
            .allow_path(p, AccessMode::ReadWrite)
            .with_context(|| format!("granting read+write access to the rw-bind {p}"))?;
    }
    for p in &config.profile.unix_sockets {
        caps = caps
            .allow_unix_socket(p, UnixSocketMode::Connect)
            .with_context(|| format!("granting the unix socket {p}"))?;
    }
    // Network: the shared host netns stays open (the network
    // default); `--network=none` also installs the static block.
    if config.network == crate::sandbox::namespaces::NetworkMode::None {
        caps = caps.block_network();
    }
    // Signal / IPC modes per profile (the defaults are the
    // restricted ones).
    match config.profile.signals.as_str() {
        "isolated" => caps = caps.set_signal_mode(SignalMode::Isolated),
        "all" => caps = caps.set_signal_mode(SignalMode::AllowAll),
        other => bail!("profile signals {other:?} is not \"isolated\" or \"all\""),
    }
    match config.profile.ipc.as_str() {
        "shm" => caps = caps.set_ipc_mode(IpcMode::SharedMemoryOnly),
        "full" => caps = caps.set_ipc_mode(IpcMode::Full),
        other => bail!("profile ipc {other:?} is not \"shm\" or \"full\""),
    }
    Ok(caps)
}

// ---- the ptrace-deny filter (task 8.7, the per-sandbox debugger
// gate) ----

/// BPF / seccomp constants (the kernel ABI; nono keeps its copies
/// private, so this gate carries its own). The instruction-encoding
/// fields (`code`/`jt`/`jf` of `sock_filter`) are 16-bit; `k` is
/// 32-bit and holds the return value, the `seccomp_data` offset, or
/// the compared value.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
// `struct seccomp_data { int nr; __u32 arch; __u64 rip; __u64 args[6]; }`
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `SECCOMP_SET_MODE_FILTER` (the `op` of `seccomp(2)`).
const SECCOMP_SET_MODE_FILTER: u32 = 1;

#[cfg(target_arch = "x86_64")]
const AUDIT_NATIVE_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "x86_64")]
const SYS_PTRACE: u32 = 101;
#[cfg(target_arch = "aarch64")]
const AUDIT_NATIVE_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "aarch64")]
const SYS_PTRACE: u32 = 112;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the ptrace-deny filter needs the native audit arch + ptrace nr");

/// The BPF program of the ptrace-deny filter (task 8.7).
///
/// Program (jump offsets are relative to the *following*
/// instruction, as in nono's own filters):
///
/// ```text
///  0: ld  [arch]
///  1: jeq NATIVE_ARCH -> +1          ; skip the mismatch return
///  2: ret EPERM                      ; non-native ABI
///  3: ld  [nr]
///  4: jset X32_BIT (jt=0, jf=1)      ; X32 marker is in the *nr*
///  5: ret EPERM                      ; ... field: hit -> reject
///  6: ld  [nr]
///  7: jeq SYS_PTRACE -> +1
///  8: ret ALLOW                      ; every other syscall
///  9: ret ERRNO | EPERM              ; ptrace(2)
/// ```
///
/// Installed as a **second** seccomp filter, *after* nono's
/// seccomp-notify filter (so it is evaluated **first** — seccomp
/// filters run newest-first; a `SECCOMP_RET_ALLOW` passes the
/// syscall on to the next, older filter, while the only terminal
/// verdict this program issues is its own `ERRNO`). `ALLOW` lets
/// everything but `ptrace` fall through to nono's filter, whose
/// openat notify and AF_UNIX trap still apply unchanged. No
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` here: only one filter per
/// process may own a listener fd (nono's already does) — this
/// plain filter needs none.
///
/// The architecture guard returns `EPERM` on a mismatch, exactly
/// like nono's main filter: compat-ABI processes are already dead
/// under that guard, so this changes nothing for them.
///
/// The X32 check loads the **syscall number**, not the arch field:
/// `syscall_get_arch()` never reports the X32 marker on x86 — it
/// sits in the high bit of `nr` (`__X32_SYSCALL_BIT`), so a check
/// against `arch` is dead code. The `jt=0, jf=1` encoding is
/// nono's own arch-guard convention (both jump offsets are
/// explicit, relative to the *following* instruction: the hit
/// falls into the return, the normal number skips it). Do not
/// "simplify" it to `jt=1, jf=0` or to an arch load: both
/// mis-evaluate on current kernels (7.3.x) and reject **every**
/// syscall (LESSONS #52).
fn ptrace_deny_filter() -> Vec<libc::sock_filter> {
    let eperm = SECCOMP_RET_ERRNO | (libc::EPERM as u32);
    vec![
        // 0: load the audit architecture
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        },
        // 1: native arch? (jump over the mismatch return)
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_NATIVE_ARCH,
        },
        // 2: non-native ABI: reject
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: eperm,
        },
        // 3: load the syscall number (the X32 marker bit lives in
        // nr, not in the arch field — see the note above)
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        // 4: X32 marker set (jt=0: fall into the reject below);
        // normal number (jf=1: skip the reject)
        libc::sock_filter {
            code: BPF_JMP | BPF_JSET | BPF_K,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        },
        // 5: X32 ABI: reject
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: eperm,
        },
        // 6: load the syscall number
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        // 7: ptrace? (jump over the allow)
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: SYS_PTRACE,
        },
        // 8: every other syscall: allow (fall through to nono's
        // filter, which then applies its own program)
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // 9: ptrace(2): reject (the debugger gate)
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: eperm,
        },
    ]
}

/// Install the ptrace-deny filter as a second (stacked) seccomp
/// filter in this process. Must run after nono's filter is
/// installed (it is evaluated first, newest-first) and after
/// `NO_NEW_PRIVS` is set (nono's `install_raw` sets it) — the
/// filter then locks in for this process and, across fork, for
/// the whole app tree; it can never be removed.
fn install_ptrace_deny_filter() -> Result<()> {
    let filter = ptrace_deny_filter();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        // The kernel copies the program out of this memory; the
        // `const` → `mut` cast is the ABI shape of `sock_fprog`
        // (libc 0.2 has no `seccomp_filter` yet).
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` references the live `filter` vector; the
    // seccomp syscall copies the program into the kernel.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("installing the ptrace-deny filter");
    }
    Ok(())
}

/// Apply the policy in this (child) process. Stages, in this
/// order (decision #22 — the notify filter must be the *only*
/// NEW_LISTENER filter, and it must precede the Landlock floor so
/// the supervisor sees every path the floor would block):
///
/// 1. **Prepare** the Landlock policy (`detect_abi` +
///    `prepare_landlock_with_abi`): the rule paths are opened here,
///    *before* the filter exists. If this ran after the filter, its
///    `openat`(O_PATH) calls would be trapped and B would block on
///    its own install, with no supervisor yet holding the listener.
/// 2. **Install** the combined seccomp-notify filter (it sets
///    `no_new_privs` itself).
/// 3. **`apply_raw`**: builds the ruleset from the pre-opened fds
///    (no path opens — nothing left to trap), re-asserts
///    `no_new_privs` (locking the single-extent identity — #10) and
///    `restrict_self` — the irreversible floor.
///
/// `block_ptrace` (task 8.7, the per-sandbox debugger gate): when
/// true (a run without `--debug`), stage 2.5 stacks a second
/// seccomp filter on top of the notify filter that rejects
/// `ptrace(2)` (see [`install_ptrace_deny_filter`]).
///
/// Returns the notify listener fd. It has no CLOEXEC flag, so it
/// survives the app's exec (the supervisor services it — #23).
pub(crate) fn apply(caps: &CapabilitySet, block_ptrace: bool) -> Result<OwnedFd> {
    let abi = nono::sandbox::detect_abi()
        .map_err(|e| anyhow::anyhow!("detecting the Landlock ABI: {e}"))?;
    let prepared = nono::sandbox::prepare_landlock_with_abi(caps, &abi)
        .map_err(|e| anyhow::anyhow!("preparing the Landlock policy: {e}"))?;
    let notify = nono::sandbox::prepare_seccomp_af_unix_filter()
        .with_openat_notifications()
        .install_raw()
        .map_err(|e| {
            anyhow::anyhow!(
                "installing the seccomp-notify filter failed at {:?} ({})",
                e.stage(),
                std::io::Error::from_raw_os_error(e.errno())
            )
        })?;
    if block_ptrace {
        install_ptrace_deny_filter()?;
    }
    prepared.apply_raw().map_err(|e| {
        anyhow::anyhow!(
            "applying the Landlock floor failed at {:?} ({})",
            e.stage(),
            std::io::Error::from_raw_os_error(e.errno())
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(notify) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    /// The ptrace-deny program is exactly the ten-instruction
    /// layout the comment above spells out: arch guard (native
    /// check, X32 check, both `EPERM` on mismatch), then the
    /// `ptrace` number check with `ALLOW` on the fall-through and
    /// `ERRNO|EPERM` on the hit. The jump offsets are relative to
    /// the *following* instruction: insn 1 jumps over insn 2,
    /// insn 4 jumps *into* insn 5 (X32 hit) / over it (normal
    /// number), insn 7 jumps over insn 8.
    #[test]
    fn ptrace_deny_filter_is_the_ten_instruction_program() {
        let f = ptrace_deny_filter();
        assert_eq!(f.len(), 10);
        let eperm = SECCOMP_RET_ERRNO | (libc::EPERM as u32);
        let ld_arch = libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        };
        let ld_nr = libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        };
        assert_eq!(f[0], ld_arch);
        assert_eq!(
            f[1],
            libc::sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_NATIVE_ARCH
            }
        );
        assert_eq!(
            f[2],
            libc::sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: eperm
            }
        );
        // insn 3 loads the *number* (not the arch): the X32
        // marker bit lives in `nr`, and the arch field is always
        // the native audit arch — nono's own guard does the same
        // (the ld-[arch] variant bricks the process on this
        // kernel; LESSONS #52)
        assert_eq!(f[3], ld_nr);
        assert_eq!(
            f[4],
            libc::sock_filter {
                code: BPF_JMP | BPF_JSET | BPF_K,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT
            }
        );
        assert_eq!(f[5], f[2]);
        assert_eq!(f[6], ld_nr);
        assert_eq!(
            f[7],
            libc::sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: SYS_PTRACE
            }
        );
        assert_eq!(
            f[8],
            libc::sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW
            }
        );
        assert_eq!(f[9], f[2]);
    }

    /// Live semantics: install the filter in a *forked child*
    /// (never in the test process — seccomp is irreversible),
    /// have the child `ptrace(PTRACE_TRACEME)` and report, and
    /// assert the `EPERM` the gate promises. The child's `write`
    /// must pass through the `ALLOW` fall-through (only `ptrace`
    /// is trapped).
    #[test]
    fn ptrace_deny_filter_blocks_ptrace_in_a_child() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut r = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut w = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        // SAFETY: fork(2); the child below only exits, never returns.
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                // Keep only the write end, install, probe. The
                // install needs `NO_NEW_PRIVS` (or `CAP_SYS_ADMIN`
                // — the test has neither): in the real pipeline
                // nono sets it before the notify filter, and this
                // filter is stacked on top of that; mirror the
                // order here.
                drop(r);
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    0,
                    "PR_SET_NO_NEW_PRIVS: {}",
                    std::io::Error::last_os_error()
                );
                install_ptrace_deny_filter().expect("installing the gate filter");
                // PTRACE_TRACEME (0): no target, a self request —
                // the gate's verdict on the syscall number.
                let res = unsafe { libc::syscall(libc::SYS_ptrace, 0i64, 0i64, 0i64, 0i64) };
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                let _ = w.write_all(&[(res == -1) as u8, errno as u8]);
                std::process::exit(0);
            }
            Ok(nix::unistd::ForkResult::Parent { .. }) => {}
            Err(e) => panic!("test setup: fork: {e}"),
        }
        drop(w);
        let mut out = [0u8; 2];
        assert_eq!(r.read(&mut out).unwrap(), 2);
        assert_eq!(out[0], 1, "the child's ptrace must have failed");
        assert_eq!(out[1], libc::EPERM as u8, "…with EPERM, the gate's errno");
    }
}
