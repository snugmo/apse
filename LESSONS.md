# LESSONS

Short, living record of hard-won lessons from working on apse, so future
sessions (human or agent) don't have to re-learn them. Each entry is a
takeaway; for full context follow the `source:` link to the relevant
post-mortem (in `docs/postmortems/`) or commit.

**Cultivate this file.** When a change teaches something durable, add one line.
Keep entries to a few sentences; if one grows long, promote it to a post-mortem
under `docs/postmortems/` and link here. This file is a *pointer*, not the
write-up.

## Working with the code

1. **For "first/last N" logic, test the multi-element path, not just the
   one-element path.** `VecDeque::split_off(n)` keeps `0..n` and *returns*
   `n..len`; to consume the first N in arrival order the primitive is
   `drain(0..take)`. The fd-misrouting bug was invisible in single-fd tests
   where `take == len` made the wrong call accidentally correct.
   — *`docs/postmortems/fd-swap-fix-plan.md` §1, §5; commit `88d237e`.*

2. **In a security-sensitive path, name the category of the bug before
   fixing or reporting it.** The fd mispairing sat in the clipboard path but
   was a *data-integrity* bug, not a *security* regression: the gate's
   forward/drop decision keys on the object id + origin, never on the fd
   itself. — *post-mortem §4.*

3. **Read the load-bearing lines at the actual line numbers before trusting
   a handoff doc.** The confidence in the fix came from reading the real
   `split_off` call and the `wire::parse_message` `pop_front` contract, not
   from the document alone. — *post-mortem §2, §9.*

10. **Anchor a rate-limit window on the last *emitted* event, not on every
    suppressed one.** If every event reset the window, a continuous stream
    would suppress itself forever; anchoring on the emission gives one event
    per window. The copy-out rate limit does this; the audit log keeps the
    suppressed ones on record.
    — *commit `3931f52` (the Phase 6 follow-up).*

11. **A daemon with a long-lived control channel plus many short-lived
    clients: run the control channel in the main thread and the client work
    on spawned threads — never the reverse.** The old design parked the main
    loop in the 30-second consent wait, making a second pending prompt
    structurally impossible. Fix: main owns the decision socket on `poll(2)`;
    each connection parks on a per-prompt condvar; decision and queue removal
    stay under one lock. — *commits `6365ae5`, `b186c13`.*

## Writing tests

4. **Write the test, watch it fail, then fix (red → green).** Confirm the
   test fails on the current buggy code with the *exact* expected symptom,
   then apply the fix and confirm it passes. — *post-mortem §6–7.*

5. **Prove batching is structural, not a race, before calling a test
   "deterministic".** Here `blocking_dispatch` drains all pending events
   before flushing, so two requests in one dispatch pass always coalesce
   into one `sendmsg`. — *post-mortem §3.*

6. **Reuse the existing harness; don't reinvent the scaffolding.** The
   regression test reused the clipboard harness, adding only a second data
   offer plus two back-to-back `receive` calls. — *post-mortem §6.*

## Toolchain and scope

7. **Establish the toolchain baseline before blaming your own diff.** The 44
   `cargo fmt --check` hunks were *pre-existing* rustfmt 1.10.0 drift.
   Determine the baseline (which files, which tool version) before
   attributing a gate failure to your edits.

8. **Keep the diff to the defect.** The fix touched exactly `forward()` in
   `src/proxy/mod.rs` and the new test. Related defects found in the same
   review get their own `TASKS.md` entry and commit.

## Gotchas

9. **Wayland macros live at `impl` level, not inside `fn event`.** Placing
   `event_created_child!` inside `fn event` produces a confusing *runtime*
   panic deep in `wayland-client`'s event queue. The macro must be a sibling
   of `fn event`, inside the `impl`. — *`tests/proxy_integration.rs` (Srv4).*

12. **In a mode-based binary, global clap `required*` attributes break the
    modes that don't need the argument.** `--listen` had
    `required_unless_present = "socket_activation"`, so the `--decide`
    one-shot demanded a fake listen path. Keep such arguments optional at
    parse time; enforce in `validate()` for the specific modes that bind.
    — *commit `26f54c6`.*

13. **Don't re-exec a socket-activated process to "reload" it.** The
    activated fd may carry `FD_CLOEXEC` (`execve` closes it), and where the
    security context is stamped *on* that fd the compositor may refuse to
    re-stamp it. The SIGHUP rebuild branches: `--listen` re-execs in place;
    socket-activated exits cleanly for a systemd restart. — *commits
    `e390b32`, `6923ea5`.*

14. **`CString::new` and `CString::from_vec_with_nul` have opposite
    conventions about the trailing NUL.** `new` treats a trailing NUL as an
    *interior* NUL and rejects it; `from_vec_with_nul` requires the last
    byte to already be NUL and never appends one. To convert NUL-free bytes,
    append the NUL first, then call `from_vec_with_nul`.
    — *`src/proxy/mod.rs` (`osstring_bytes_to_cstring`).*

15. **A forked child must inherit no live OS threads — from any runtime,
    global *or* local.** (a) `zbus::blocking` (v5) drives futures on a
    process-global `tokio` runtime in a `static OnceLock`; in a forked child
    the `OnceLock` still reports it built while its workers are gone, so
    `block_on` hangs silently. (b) Even a fresh **local** multi-thread
    runtime is unsafe: dropping it does not join its workers, so they linger
    across the fork and `std`'s global `thread_info` mutex is left owned by
    a vanished thread — the first thread the child creates deadlocks on it.
    Fix: drive the *async* API on a **current-thread** runtime.
    — *the clipboard-branch merge (Phase 7); `src/systemd.rs`
    (`with_local_runtime`), `src/sandbox/mod.rs` §5.4.*

16. **Env-mutating tests must run single-threaded; a lock only against other
    `setenv` callers is not enough.** `std::env::set_var`/`remove_var` are C
    `setenv`/`unsetenv` and are UB when *any* other thread reads the
    environment concurrently — not just another `with_env`, but plain
    readers like `temp_dir`, xdg, and clap `getenv`. Fix:
    `cargo test -- --test-threads=1` (wired into CI).

17. **A queue filled by concurrent threads is ordered by a sequence stamped
    at the sequential entry point, never by lock order.** The broker's
    prompts were registered by per-connection threads, so *which* thread
    grabbed the lock first decided the order — and the integration test
    flaked. Fixed by stamping each connection with a monotonic sequence in
    the `poll(2)` accept loop and ordering by `(seq, id)`.

18. **When a spawner passes an fd to a child, the argv is half the contract
    — and its absence fails silently.** Phase 7.2's socketpair rewrite
    handed `xdg-dbus-proxy` its lifetime fd on fd 3 but dropped the
    *`--fd=3` flag*: the proxy never wrote its sync byte, so the sidecar
    parked forever. Related (GLib 2.90): `g_io_add_watch(G_IO_ERR|G_IO_HUP)`
    is polled with *zero* requested events (GLib masks those bits out); the
    fd must be **non**-CLOEXEC to survive `execve`.

19. **The `-listenfd` contract: the *spawner* must `listen(2)` before the
    handoff.** Xwayland's `-listenfd` path (libXtrans `SocketReopen`) adopts
    the fd *as-is* and never calls `listen`. Hand over an unlistened socket
    and `accept(2)` fails `EINVAL` on every readiness wake: an infinite
    flood at 100% CPU. sway's own spawn is the model.

20. **The kernel clears `PR_SET_PDEATHSIG` on any exec that changes the
    process's *security credentials* — not just setuid, and not just
    `AT_SECURE`.** On this (SELinux-enforcing) machine `Xwayland` execs into
    `xserver_t`; `security_bprm_committing_creds` clears the death signal
    while `AT_SECURE` stays *unset* (so `LD_PRELOAD` still works). Fix: a
    3-line `LD_PRELOAD` shim whose constructor re-sets
    `PR_SET_PDEATHSIG(SIGTERM)` after the transition. Xwayland's `-once` is
    *XDMCP-session* semantics (a no-op for non-XDMCP rootless). — *the
    Phase 7.3 verification; `src/xwayland.rs` (`ensure_shim`), decision #37.*

21. **checkpolicy 3.11 (Fedora 45): module compilation is `checkmodule`, not
    `checkpolicy`.** A module `.te` must start with `module <name> <ver>;`
    and carry a `require { … }` block; the policy version tops out at 24;
    base *type attributes* referenced in rules are re-declared in the module
    and merge by name at load. — *the phase 8.2 module; `selinux/`.*

22. **Build a capability set against paths that exist *where the set is
    built*.** S builds the supervisor's `CapabilitySet` against the
    *in-sandbox* instance-dir path, but nono's `allow_path` validates
    existence at build time — that path exists on the host only when the
    session XDG *is* `/run/user/<uid>`. With a divergent XDG the build
    fails, the supervisor disables itself *silently*, and every trapped
    syscall dies `ENOSYS`. — *`tests/sandbox_integration.rs`
    (`session_xdg`), decision #28.*

23. **Podman is two SELinux domains, and they map onto apse's two sides.**
    `crun` is `container_runtime_t`; the in-container payload is
    `container_t` (reached by *setexecfilecon* — no file `type_transition`
    into `container_t` exists). The permissive probe ran apse in both: zero
    genuine denials. The rebuilt rootfs gets `container_file_t` for free
    (the fresh `seclabel` tmpfs inherits the mounting process' exec label);
    the in-sandbox EACCESes on socket `bind` and cgroup writes are nono's
    (landlock/seccomp), not SELinux. — *the container-selinux probe
    (permissive); PLAN.md 8.2, `selinux/`.*

24. **`semodule -i file.cil` *is* a valid install path — the CIL reader
    lives in libsepol, not in the checkpolicy CLI.** A test `.cil`
    installed, committed, and its rules appeared in the live policy. The
    checkpolicy binary has no CIL input mode in this build. Gotchas:
    `mounton` is checked on *file* objects for bind-mounts; on Fedora 45
    the user session bus is dbus-broker as `unconfined_dbusd_t` with
    `/run/user/<uid>/bus` labeled `session_dbusd_tmp_t`. — *the CIL
    verification + module rework; `selinux/`.*

25. **The 3.11 module store is CIL-based, so the CIL reader is the
    universal install gatekeeper — and it validates against the *live*
    policy.** Every `semodule -i` converts to CIL at commit time. The
    reader: has **no** `(module …)` header (that is a checkpolicy *output*
    convention); validates **every** (class, permission) pair against the
    live policy's class table (permissions that *compile* under checkmodule
    can fail at install); the `.pp`→CIL writer serializes an *unresolved*
    `gen_context(…)` filecon verbatim → "Bad filecon declaration". Fix:
    embed `(filecon …)` in the module CIL. The CIL lexer has **no comment
    rule**. — *the CIL install debug; `selinux/`.*

26. **`/proc/self/attr/exec` is consumed by the next exec, so a "preserve
    state across re-exec" helper must not clobber a pending write.** The MCS
    self-narrowing writes the exec context and then re-execs through a
    shared helper whose range-preservation write would silently overwrite
    the just-written target context. Fix: read the exec attribute first and
    skip when an explicit context is already pending
    (`mcs::preserve_range`). Setting the exec context to the *same type*
    still needs `dyntransition` on the (type, type) pair. New *objects* take
    the parent's low level (`s0`) via `default_range … target low` (see
    #29). — *the MCS wiring; `src/mcs.rs`.*

27. **`checkmodule -C` (3.11) writes `typetransition` with the raw `.te`
    class — and the kernel's bprm lookup consumes only `process`.** The
    classic pipeline turns `type_transition src filetype:file target` into
    *both* a file-class and a process-class entry; `checkmodule -C` writes
    only the literal class, so its `(typetransition … file …)` compiled and
    installed fine but never fired — no AVC, no error. Fix: hand-written CIL
    `(typetransition src type process target)`. — *the transition-not-firing
    debug; `selinux/apse.cil`.*

28. **A process context is *valid* only when its role is associated with
    its type — and `setprocattr` enforces that with a silent `EINVAL`.** A
    new module type gets only `(roletype object_r TYPE)`; a shell-spawned
    process inherits `unconfined_r`, so `unconfined_u:unconfined_r:apse_t`
    was invalid. Fix: `(roletype unconfined_r apse_t)` / `(… apse_app_t)`.
    Adding the types to `mcs_constrained_type` makes MCS categories *bind*
    (process-level only; files/dirs are all `s0`, see #29). Oracle:
    `runcon user:role:type:level /bin/true`. — *the MCS no-narrowing debug;
    `selinux/apse.cil`, `src/mcs.rs`.*

29. **New objects take the *parent's* low level, not the creator's range —
    so under an `s0` parent, files/dirs/sockets are always `s0`, and there
    is *no* cross-instance object isolation via MCS.** The live policy sets
    `default_range dir/file/sock_file target low`; in `mls_compute_sid` the
    transition path copies the **parent directory's** low level. Only
    classes with *no* `default_range` (process, `unix_stream_socket`) get
    the creator's **full** range. The MCS layer isolates the **process**
    level only; object separation comes from namespaces + landlock. A record
    that fails an MLS *constrain* carries `mls=1`. — *the default_range
    investigation; `src/mcs.rs`, `selinux/README.md`, kernel
    `security/selinux/ss/mls.c`.*

30. **The kernel NUL-terminates the selinuxfs attr strings, and `str::trim`
    will not strip that.** `read_to_string` returns
    `user:role:type:range\0`; the parsed range came back as `s0\0`, the
    loop guard never matched, and apse re-execed ~260k times. Fix: truncate
    at the first NUL (`mcs::parse_label`). Second trap:
    `mls_sid_to_context` *collapses a low==high range to a single level*, so
    a narrowed `s0-s0:cN` reads back as `s0:cN` — the guard's target must
    use that form. — *the 260k-execve incident; `src/mcs.rs`.*

31. **`std::fs::write` on `/proc/self/attr/exec` carries `O_CREAT`, and on a
    fresh in-sandbox procfs that first open runs a `may_o_create` probe that
    SELinux answers with an `add_name` denial on the `attr/` directory.**
    Non-fatal (the kernel clears `O_CREAT` and re-resolves), but it logs a
    denial every run, and granting the full chain does *not* fix it (the
    open then proceeds to `i_op->create`, which the procfs attr dir has no
    handler for → `-EACCES`). Fix: `OpenOptions::write(true).truncate(true)`
    (no `O_CREAT`). — *the attr/exec O_CREAT probe; `src/mcs.rs`,
    `selinux/apse.cil`.*

32. **A confined app that runs shell *pipelines* needs a *self*-`fifo_file`
    rule — intra-app pipes carry the creator's type.** `sh -c 'a | b'`
    creates a fifo labeled `apse_app_t`, so the pipeline's operations are
    all `apse_app_t → apse_app_t fifo_file` checks. Granting only the
    *external* pipe rule left every intra-app pipeline `EACCES`-denied.
    — *the intra-app pipe gap; `selinux/apse.cil`.*

33. **`signull` (kill 0) is a process permission this kernel's base policy
    does *not* mlsconstrain — and a module CIL can't add one.** The base
    mlsconstrain constrains `ptrace`/`signal`/`sigkill`/`sigstop`/
    `transition`/`dyntransition` but **not** `signull`, so any `cN` apse
    subject may kill -0 any apse process. It can't be fixed in the module
    (libsepol rejects `mlsconstrain` in a module CIL). The grant is needed
    for `terminate_app`'s kill -0 liveness probe; the cost is that the probe
    is not category-scoped. — *the signull investigation;
    `selinux/apse.cil`, `src/sandbox/mod.rs` (`terminate_app`).*

34. **A `stat`-based existence check conflates *absent* with *inaccessible*
    — and `Path::is_file()` is exactly that check, so a SELinux denial
    silently degrades the profile lookup.** A *denied* `getattr` or `search`
    on any ancestor makes `is_file()` return false *exactly the same way* as
    the file not existing. The fallback is **silent**: the sandbox runs with
    the *wrong effective configuration*. Defense: distinguish `NotFound`
    from every other `metadata` error, and grant the confined reader the
    full read chain. — *the profile-not-applied debug;
    `src/profile/mod.rs`, `selinux/apse.cil`.*

35. **Partial or *wrong-object* grants silently degrade — a symlink carries
    the label of the fs it sits on, and `open` is not `read` on a
    directory.** (a) The sandbox's `/dev/ptmx` is a relative symlink *on*
    the fresh tmpfs `/dev`, so it carries `tmpfs_t`, not `ptmx_t`. (b)
    Fontconfig `open()`s each font directory before `getdents`-ing it;
    `open` and `read` are *separate* `dir` permissions, so a `read`-only
    grant passes the enumeration while the `open(2)` is still denied. The
    discriminating test is always the consumer actually doing the op, not
    the absence of denials. — *the enforcing-mode pty+font debug;
    `selinux/apse.cil`, `src/sandbox/mounts.rs`.*

36. **SCM_RIGHTS receive is a *separate* MAC check against the *receiving*
    process — twice, against two different labels — and a denial drops the
    fd silently (only `MSG_CTRUNC` flags it).** The kernel's
    `security_file_receive` checks the **receiver**: first `fd:use` against
    the file object's SID (for a `memfd_create`'d file that is the
    **creator's** SID), then the permissions implied by the fd's `f_mode`
    against the **inode's label** (for an anonymous fresh-tmpfs inode,
    `tmpfs_t`). Both must pass; a failure drops the fd while the message
    *bytes* arrive intact. The grant set must cover every process the relay
    touches; `ProxySocket::recv` now checks `ReturnFlags::CTRUNC` after
    every `recvmsg`. — *the enforcing-mode relay fd debug;
    `selinux/apse.cil`, `src/proxy/mod.rs`, kernel
    `security/selinux/hooks.c`.*

37. **A reaper that must live must never die on an interrupt — and
    supervision that lives only inside a process orphans everything when
    that process dies.** (a) `EINTR` was fatal in both reapers' blocking
    `waitpid`s (they block *exactly* the three signals they forward, so
    every other signal is at default disposition and interrupts `wait4`).
    (b) The `AppKillGuard` is armed at handoff; its `Drop` reads the
    instance sub-cgroup's `cgroup.procs` and SIGKILLs what is still there.
    **Remaining boundary:** a default-terminate signal *to S itself* kills
    the guard with it (`Drop` runs only on unwinding exits, not on a
    fatal-signal death) — closed by the `PR_SET_PDEATHSIG` cascade (#42).
    — *the run-#1 orphan; `src/sandbox/mod.rs` (`waitpid_retry`,
    `AppKillGuard`), decisions #13/#14/#41.*

38. **Test tooling can outlive the session that spawned it — and leave
    *input* state behind.** (a) The ydotool daemon (root, nohup'd) survived
    a mid-sequence kill holding a key pressed; a pressed key on a wlroots
    keyboard is auto-repeated by the compositor — the user's terminal
    behaved as if [enter] were broken. The fix is to destroy the *virtual*
    device. (b) A `python3 -` test helper whose coordinator died kept its
    `while not data: data = sock.recv()` loop, which then got EOF (0 bytes)
    on every call and "retried" at 100% CPU for hours. `recv() == 0` is the
    *closed* state, not "empty, try again". — *the post-restart incident
    (2026-10-30); ydotoold, `swaymsg -t get_inputs`.*

39. **Never run a probe that unshares a PID namespace and signals by numeric
    PID from inside a live desktop session — and never one without `kill()`
    auditing.** The pdeathsig probe (2026-10-31) was run via the agent's
    `bash -c` inside the `foot` scope's cgroup; the same second the
    session's own `systemd` was SIGKILL'd, and systemd tore down the
    **entire** session until the user rebooted. (a) `unshare(CLONE_NEWPID)`
    changes only `pid_for_children`, not the caller's own namespace — the
    `kill(1)`s were **no-ops** (they targeted the host's init, un-killable
    from userspace). (b) The real hazard is that a freshly created pidns
    inside a session cgroup interacts with systemd's session machinery in a
    way you cannot safely reason about; when it misfires it takes the
    session's *manager* with it. (c) Isolate and audit before you probe: run
    pidns/signal experiments in a context you can afford to lose, and arm a
    `kill()`/`tgkill()` audit rule *beforehand*. — *the 2026-10-31
    desktop-kill; pid_namespaces(7); the pdeathsig cascade (decision #42).*

40. **On 7.2, `PR_SET_PDEATHSIG` is neither inherited nor stable across
    exec — `fork` *resets* it to 0, and `execve` clears it *unconditionally*
    on any exec that changes the process's SELinux SID.** `selinux_bprm_
    committing_creds` (`security/selinux/hooks.c:2545`, commit
    `4ac212ad4e8f`) sets `current->pdeath_signal = 0` whenever the exec
    changes the SID — a confined run does — and no permission can prevent it
    (this policy *grants* `noatsecure` on the `apse_t` → `apse_app_t`
    transition, so the `secureexec` path does not even fire). Consequences:
    (a) every cascade link must set its value *after its own fork*; (b) a
    process that execs into a different SELinux domain needs the post-exec
    `LD_PRELOAD` shim to re-arm the signal (belt and bridle are both
    load-bearing); (c) a signal the process will have *blocked* at delivery
    never fires, so a pdeathsig must be one the receiver handles (A keeps
    TERM/INT/HUP blocked, hence `SIGUSR1`). `PR_GET_PDEATHSIG` writes the
    value to the pointer in `arg2` and returns 0/`-EFAULT` (the ≤ 6.x
    convention of returning the value is gone). — *the decision-#42
    implementation; `src/pdeathsig.rs`, `src/sandbox/mod.rs`,
    `src/xwayland.rs`.*

41. **A confined consumer can `mmap(PROT_EXEC)` a file only against labels
    its policy explicitly grants `file:execute` on — and on 7.2 a `filecon`
    is dead weight for created files, so the shim `.so` gets a dedicated
    type applied with `setxattr`.** On 7.2.11 a `PROT_EXEC` mapping is
    mediated as `FILE__EXECUTE` (`file_map_prot_to_av`); no base-policy type
    grants `file:execute` to `apse_app_t`/`xserver_t` on `user_tmp_t`, so
    the shim `.so` has `apse_shim_t`. `filecon` does not label created
    inodes (`OCON_FILE` is gone), so `ensure_shim` applies the label with
    `setxattr("security.selinux")`. The relabel check ends in
    `FILESYSTEM__ASSOCIATE` whose **subject is the *new* label's SID** and
    whose target is the **mount's** SID. A failed relabel degrades silently;
    the symptom is `ld.so`'s "cannot be preloaded (failed to map segment
    from shared object)". — *the decision-#42 shim; `selinux/apse.cil`,
    `src/pdeathsig.rs` (the `ensure_shim` relabel),
    `security/selinux/hooks.c`.*

42. **A vforked (or forked) child shares the parent's cred — so a pending
    one-shot exec context is consumed by the *child's* `exec`, not the
    parent's.** `ensure_shim` compiles with `cc` vforked by the std
    `Command`; in confined mode that child would be carried by the
    `typetransition` into the *app* domain. Fix: `pin_self_exec_context`
    writes the process's *current* context into `attr/exec` before
    spawning; the child's `exec` copies the cred and consumes the pending
    SID, so `cc` lands in exactly `apse_t:s0:cN`. The parent's cred keeps
    the pending SID (the child got a *copy*), so `clear_exec_context` (an
    *empty* write zeroes it) runs after the spawn on every path.
    — *the decision-#42 shim compile; `src/pdeathsig.rs`
    (`pin_self_exec_context`/`clear_exec_context`),
    `security/selinux/hooks.c`.*

43. **Rust `String`/`Vec<u8>` are *not* NUL-terminated — passing one as a
    C-string argument to a raw libc FFI call makes the kernel read past the
    allocation into stale heap bytes, producing a mangled path that fails
    `ENOENT` while every log shows the path correctly.** Fix: pass a
    `CString` (which appends the NUL). The *path* is a C string (you
    terminate it); the *value* is a counted length (the kernel NUL-terminates
    it, `kmemdup_nul`). Detector: a path-based syscall failing `ENOENT` on
    a path that logs correctly in the host language. — *the decision-#42
    shim relabel; `src/pdeathsig.rs` (`current_label`/`relabel_if_needed`).*

44. **The decision-#42 B←A belt *fires* — and only strace can see it: a
    pdeathsig delivery is a kernel-internal signal send
    (`forget_original_parent` → `group_send_sig_info`), not a `kill`/`tgkill`
    syscall, so it is invisible to any audit exit filter.** A strace of the
    S→A→B pipeline caught the delivery: on SIGKILL of A, B (inside its
    pidns) shows `--- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER,
    si_pid=0, si_uid=<sender's uid>} ---`. `si_pid = 0` is the *marker* of
    a pdeathsig delivery (the dying A is in the *ancestor* PID namespace,
    invisible in B's pidns). The cascade completes: S's `wait4` returns,
    the `AppKillGuard` sweep SIGKILLs what is left, the run exits 137.
    **Open question:** B *survived* the USR1 (the trace shows
    `restart_syscall`, which only exists when the action carried
    `SA_RESTART`); the final SIGKILL was the guard's, not the belt's. The
    leading suspect is an `SA_RESTART` USR1 action set somewhere in the Rust
    binary's ELF/dynamic-linker startup. Net: *delivery* is verified,
    *termination* is verified (by the guard); the belt's own
    terminate-disposition is not cleanly isolated and is not load-bearing
    while the guard exists. — *the decision-#42 B←A field test
    (2026-11-03); `src/pdeathsig.rs`, `src/sandbox/mod.rs`
    (`AppKillGuard`); kernel `kernel/exit.c` (`forget_original_parent`),
    `kernel/signal.c` (`send_signal_locked`).*

45. **`/proc/<pid>/` is labeled with the *target process's own context*, not
    by the `proc_t` genfs rules — so self-`/proc` access runs against the
    process's *own type*, and the 7.2 `comm_write` no longer strips the
    newline you feed it.** `security_task_to_inode` sets each `/proc/<pid>/`
    inode's sid from the task's sid; `pid_update_inode` re-labels the whole
    subtree on every credential change. So a process that execs with
    `setexecfilecon` re-labels its *own* `/proc/self/` tree into the new
    domain; the MCS narrowing's `attr/exec` write and `/proc/self/exe`
    re-exec both run against self-typed files (covered by the existing
    `apse_t → apse_t` file allow). Traps: (a) granting `proc_t file:write`
    never applies (the file is the process's own type); (b) 7.2's
    `comm_write` copies into a zero-padded buffer and passes it to
    `set_task_comm` as-is — the old `memchr('\n')` stripping is gone — so
    writing `"name\n"` leaves the newline *inside* the 15-char comm; the
    same `comm_write` only accepts the write from the owning thread group
    (`same_thread_group`, else `EINVAL`) — cross-process comm renames are
    dead. — *the comm-restore fix; `src/main.rs`, `selinux/apse.cil`;
    kernel `fs/proc/base.c` (`comm_write`, `pid_update_inode`),
    `security/selinux/hooks.c` (`selinux_task_to_inode`).*

46. **A `typetransition` makes the exec *possible*; the exec-time cred hooks
    then check `noatsecure`/`rlimitinh`/`siginh` against the *new* SID, and
    their denial is a *silent degradation*, not a failure — while the real
    blockers of a satellite are its *inherited* fds (checked against the
    creator's type, `accept` included) and the teardown signals.** The
    `xwayland` satellite's exec into `xserver_t` was never blocked by the
    transition itself. On 7.2.15 three exec hooks each check the new SID
    and *none aborts the exec*: you only find out from the audit log, and
    the child runs with quietly-downgraded state (the `apse_app_t` leg
    never showed the triple because this policy grants `noatsecure` on that
    transition). The real failures: (a) the displayfd socketpair, the
    listening X socket, and the /dev/null dup carry the *creator's* SID
    (`apse_t`); the load-bearing one is `accept` — without it every X
    client connection piles up in the kernel backlog, the server spins on
    `accept() failed`, and the display looks *up* while serving nothing.
    (b) The TERM→2s→KILL teardown needs `process (signal sigkill)` on the
    transition rule. Lifecycle surprise: Xwayland *creates* its `-auth`
    file on startup and **unlinks it again on a clean shutdown** — the
    missing-file error is non-fatal. — *the confined-mode verification of
    the `xwayland` satellite (2026-11-04, kernel 7.2.15);
    `selinux/apse.cil`, `src/xwayland.rs`; kernel
    `security/selinux/hooks.c`.*

47. **The `wl_data_source` wire does not say whether its `send` (serve) is
    clipboard or drag — a source object is shared by both — and the v4
    protocol has no `finished` event: a drag ends only on `cancelled`,
    `dnd_finished`, or `destroy`, and `dnd_drop_performed` does *not* end
    it.** The 6.5.5 refinement tracks the active drag in the relay: the
    last `start_drag`'s source (client-side only), cleared on
    `cancelled`/`dnd_finished`/`destroy`. Serves on that source get
    `selection=drag`; every other stable source's stays `clipboard`.
    — *the 6.5.5 `serve`-label drag refinement;
    `src/proxy/clipboard.rs` (`active_drag_source`), `src/proxy/mod.rs`,
    `tests/proxy_integration.rs`.*

48. **In ripgrep 15, `--no-ignore` does *not* search hidden directories —
    the hidden-file axis is a separate flag (`-./--hidden`; `-u` is now
    `--unrestricted`).** `--no-ignore` only disables *ignore files*; the
    hidden-file skipping is its own axis. A "zero matches" sweep done with
    `--no-ignore` silently misses everything under `.github/`, `.idea/`, and
    friends. The reliable "is it in the repo" check is `git grep` (searches
    the index — every tracked file, hidden or not). — *the wlsctx→apse
    rename (2026-11-06); ripgrep 15.2.0 `--help`.*

49. **Baked lettering (one `<path>` per glyph, no `<text>`) is a *snapshot
    of a font*, not text — reword or rename and every glyph must be
    rebaked; and fontTools' `getBestCmap()` is keyed by *integer codepoint*,
    so a string-keyed lookup fails silently.** The `wlsctx`→`apse` rename
    updated the header SVGs' `aria-label`/`<title>` but left the wordmark's
    six baked glyphs spelling `wlsctx`: a rename sweep that greps the string
    finds nothing. The string-keyed cmap trap: `c in cmap` with `c` a `str`
    against integer keys silently drops every face; the correct form is
    `cmap[ord(c)]`. — *the header rebake (2026-11-06);
    `assets/apse-header{,-tagline}.svg`, `AGENTS.md` (`assets/`).*

50. **SVG has no quadratic Bézier syntax, and fontTools' `Qu2CuPen` keeps
    quadratics by default — a baker that records only `curveTo` drops every
    segment it did not convert.** `Qu2CuPen`'s default `all_cubic=False`
    converts only the quadratic runs it deems necessary and passes the rest
    through as `qCurveTo`; a recording pen handling
    `moveTo`/`lineTo`/`curveTo`/`closePath` only silently drops them. A
    uniform y-flip reverses *all* contours together and the nonzero rule
    only cares about *relative* winding — so a uniform flip is never the
    culprit. Fix: `Qu2CuPen(rec, max_err, all_cubic=True)` plus an assert
    that no other pen op reaches the recorder. — *the header rebake fix
    (2026-11-06); `scripts/bake_header.py`, `scripts/verify_header.py`.*

51. **The exit status of a failed *redirection* is shell-specific (bash: 1,
    dash: 2, POSIX only guarantees "non-zero").** The supervisor's
    write-denial probe asserted `a=1` (bash) but got `a=2` on Ubuntu (dash).
    Fix: normalise *in the script* (`cmd && a=0 || a=1`). — *the
    ubuntu-26.04 CI second pass (2026-11-06); `src/sandbox/supervise.rs`.*

52. **A sandboxed app inherits the *launcher's* CWD, not its own — and in a
    private-home sandbox that path may not exist, so an app that
    `chdir(cwd)`s before its exec (foot's `slave_spawn`) dies on a vanished
    directory.** B inherits S's CWD (the host launch dir); in private-home
    mode the rootfs build replaces the real home, so the inherited CWD
    points at a path that no longer resolves. Fix: B `chdir`s to the app's
    home *before* the exec, and before the seccomp-notify filter and
    Landlock floor are installed. — *decision #43 private-home, the foot
    `slave_spawn` failure (2026-11-11, kernel 7.2.15); `src/sandbox/mod.rs`
    (the B-side chdir), `src/sandbox/mounts.rs` (`chdir`); foot 1.28
    `slave.c:397–401,554`.*

53. **A *module* type joins no base-policy attributes by default, so the
    sweeping grants that make stock `*_exec_t` binaries manageable (unconfined's
    `file_type` file lifecycle, including `unlink`) never reach it — and the
    fix is to opt the type into the *standard attribute set*, not to enumerate
    permissions by hand.** `unconfined_t` (via `files_unconfined_type`) has a
    catch-all `allow … file_type:file { … unlink … }`; base types like
    `ssh_exec_t` are `file_type` members, so `sudo rm` "just works". A module
    type (`apse_exec_t`) joins no attribute unless the module says so — so
    the *delete* leg (`unlink`) had been omitted, and `sudo rm
    /usr/local/bin/apse` failed with a bare `{ unlink }` denial. Fix: opt
    into the same attribute set the base policy gives `ssh_exec_t`/
    `sudo_exec_t` (`file_type`, `exec_type`, `entry_type`,
    `application_exec_type`, `non_auth_file_type`, `non_security_file_type`).
    Auditing *before* joining (`sesearch --allow -t <attr> -dt -p write`)
    shows the feared write hole does not exist: the only user-space writer
    of `file_type` is `unconfined` itself, the writers on
    `non_auth_file_type`/`non_security_file_type` apply *identically* to the
    ssh binaries (parity, not a delta), and no write grant reaches
    `apse_t`/`apse_app_t`. `entrypoint` is the one permission the attributes
    do not cover — granted explicitly. Related trap: `filesystem:associate`
    is per-filesystem-*type* — the module grants it for `fs_t` but not
    `tmpfs_t`, so a scratch file can be `chcon`'d on `/` but not on `/tmp`.
    — *the `sudo rm /usr/local/bin/apse` failure and the attribute-parity
    rework (2026-11-11/12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

54. **On 7.2 the inotify watch is a MAC check (`inotify_add_watch` is
    mediated against the `watch` permission — the permission existed for
    years but this kernel is the first to enforce it) — and an interactive
    shell's full state pattern is a predictable denial class, every fix of
    which is user-data-scoped or read-only — none opens the jail.** Fish in
    the private home produced ~120 denials: (a) `dir (lock watch)` on its
    *own* config dir; (b) `file (setattr rename)` on its *own* state files
    (atomic save); (c) `dir (read)` — and, once granted, `dir (open)` — on
    every enumerated dir (`open(2)` on a dir is a *separate* check from
    `getdents`, #35); (d) probe ioctls against files (the loader probes the
    just-opened exe/`.so` with a tty ioctl at exec); (e) `dir (getattr)` on
    the root dir's remaining entry types. All fixes are additions to the
    existing per-type grant sets — user-data-scoped or read-only. Detector:
    a 7.2 `watch` denial on a directory the app *owns* is not a jail
    escape. — *the fish-in-foot denial round (2026-11-12, kernel 7.2.15,
    enforcing); `selinux/apse.cil`.*

55. **On audit 4.2.1 (Fedora 45), `ausearch -ts <time>` — and `--start`
    with a relative or bare-keyword spec (`10min`, `60min`, `today`) —
    silently matches *zero* records, so a "zero denials" verification
    passes vacuously.** `--start recent` and absolute timestamps work; the
    relative forms return an *empty result set without error*. Detector: a
    "clean" audit window that contradicts observed behavior — sanity-check
    against a record you *know* exists, or use a file-grep baseline.
    — *the fish-in-foot denial round's verification (2026-11-12); audit
    4.2.1 (`ausearch --start`/`-ts`).*

56. **The module-store CIL dialect has no `filetrans` keyword — a
    *filename* transition is spelled as the five-field `typetransition`
    (`src tgt class "name" child`), the quoted name distinguishing it from
    the four-field process form.** `semodule -i` on `(filetrans …)` fails
    `Unknown keyword filetrans`. The CIL reader has only `typetransition`,
    with the arity selecting the meaning. — *introducing `apse_state_t`
    (2026-11-12, libsepol 3.11, kernel 7.2.15); `selinux/apse.cil`.*

57. **On 7.2, `filecon` does not label *created* inodes — a new inode's
    label comes only from (a) the mountpoint default, (b) the process'
    `create_sid`, or (c) a filetrans; and the no-rule default of
    `security_compute_sid` is the *parent's* own type, so one named
    filetrans labels an entire subtree, any depth, on any fs.**
    `selinux_determine_inode_label` consults exactly those three sources; a
    filecon matching the path is used by `restorecon`/`setfiles`, never at
    creation. Making the per-app state tree a dedicated type takes: a named
    filetrans on the *root* dir, no per-child rules (children fall through
    to the parent's type), and the MLS range follows the parent's low level
    (`s0`). Pre-existing inodes need a one-time setxattr walk
    (`relabel_state_tree`). Detector: a newly created dir keeps the
    parent's or fs-default label even though a filecon "should" match —
    check that something actually *transitions* to the type at creation.
    — *`apse_state_t` (2026-11-12, kernel 7.2.15, `hooks.c`
    `selinux_determine_inode_label` + `ss/services.c`
    `security_compute_sid`); `selinux/apse.cil`,
    `src/sandbox/mounts.rs` (`relabel_state_tree`).*

58. **The unconfined home-dir access on the stock home types is
    *attribute-mediated* — a dedicated non-attribute type gets none of it,
    so the user's lifecycle must be mirrored by explicit grants; and the
    private-home rootfs makes `mounton` on that tree load-bearing for
    *both* the confined A and the unrelabeled test-suite pipeline.**
    `apse_state_t` joins no attribute, so `unconfined_t` needed the full
    lifecycle mirrored by name (dir `add_name create getattr ioctl lock
    mounton open read remove_name rmdir search setattr unlink watch write`,
    file `… rename …`, lnk_file). The test suite's apse is unrelabeled
    (`unconfined_t`) and runs the *same* pipeline — the missing `mounton`
    surfaced as 18 `rootfs construction failed: … Permission denied` test
    failures. `mounton` matters for the binds *specifically because of the
    home substitution*: once the home bind has replaced `/home/user`, every
    later XDG bind target resolves to a dir *of the tree* — source and
    target are both `apse_state_t`. Detector: an EACCES on `mount(2)` where
    both source and target dirs are your own dedicated type — think
    `mounton`, not `search`/`read`. — *`apse_state_t` (2026-11-12, kernel
    7.2.15, enforcing); `selinux/apse.cil`.*

59. **`/proc/<pid>` carries the *target process's* context (its whole
    subtree does), so a tool that stats or ioctls its own process entry in
    /proc needs a *self-referential* grant.** `ps` in a sandboxed foot
    produced: (a) `proc_t:dir open` + `read`; (b) `sysfs_t:dir open` +
    `read`; (c) `sysctl_kernel_t:dir search` + `file read` (`pid_max`); (d)
    `apse_app_t:dir ioctl` on its *own* `/proc/<pid>` dir (the tty probe).
    (d) is MCS-safe: a single-level `s0:cN` subject dominates only
    same-category objects. Detector: a `denied { ioctl }` on a `/proc/<pid>`
    path with scontext == tcontext modulo level — the object is self-
    labeled; the fix is a self grant, not a `proc_t` grant. — *`ps ax` in
    the sandboxed foot (2026-11-12, kernel 7.2.15, enforcing);
    `selinux/apse.cil`.*

60. **`statfs(2)` is mediated against the *mounted filesystem's* type — the
    `filesystem` class, the `filesystem_type` attribute family — never
    against the path's label, so `df` needs a grant on that family, and one
    attribute covers all of it.** The check's target is the superblock's
    SID; `getattr` on this class is superblock metadata (fs type name,
    total/free size) and reads no file content — which is what makes the
    attribute grant safe. One adjacent shape: `df` also stats
    `/proc/sys/fs/binfmt_misc` — `sysctl_fs_t`, needing `dir (getattr
    search)` plus `file (getattr open read)`. Detector: a `denied {
    getattr }` with `tclass=filesystem` — grant the *attribute*, not the
    one type in the denial line. — *the `df /run` denials (2026-11-12,
    kernel 7.2.15, enforcing); `selinux/apse.cil`.*

61. **`lnk_file:getattr` (the lstat of the link itself) and `lnk_file:read`
    (the readlink) are *separate* checks — without the former, `ls -la`
    prints `l??????????`.** The sandbox's ptmx is a *relative* symlink on
    the fresh tmpfs `/dev`, so it carries `tmpfs_t`, not `ptmx_t`. A
    listing lstats the link before it readlinks it; a `read`-only grant
    degrades the entry to `l??????????`. Detector: an `l??????????` entry
    alongside a `lnk_file` *getattr* denial — add the getattr, not another
    read. — *the `ls -la /dev` ptmx denial (2026-11-12, kernel 7.2.15,
    enforcing); `selinux/apse.cil`.*

62. **Fedora labels most of `/usr/bin/*` with per-purpose exec types, not
    `bin_t` — so a tool that stats every entry it enumerates (fish's
    completion) targets the `exec_type` attribute, the superset of every
    `*_exec_t`.** The directory grant lets you see the names, but the
    per-entry stat is a separate check against each entry's own type. The
    complete target is `exec_type` (`file:getattr`, `lnk_file:(getattr
    read)`). The grant is read-only by construction. Detector: per-entry
    `getattr` denials spread across a *set* of `*_exec_t` types — the
    target is an attribute. — *fish completion in the sandbox
    (2026-11-12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

63. **A tool that maps its controlling tty back to a `/dev/pts/<N>` name
    *enumerates* the devpts root — in the sandbox, the fresh per-instance
    one — so the `devpts_t:dir` grant needs `open` + `read`, not just
    `search`.** Fish asks the kernel for its tty, then walks `/dev/pts/`
    looking for the matching inode. This is the #54/#59 open-vs-read class:
    `open(2)` on a dir is a separate check from `getdents`, and `search`
    covers neither. Scope: the enumeration is against the *fresh* per-
    instance devpts (only this instance's ttys, `s0`) — the host's devpts
    is never visible inside the sandbox. — *the pty-driven fish
    verification (2026-11-12, kernel 7.2.15, enforcing);
    `selinux/apse.cil`.*

64. **The `cwd`/`exe`/`root` links of `/proc/<pid>` are labeled with the
    *target process's own* type (the whole pident tree, #45) — so a listing
    of `/proc/self` hits a *self*-labeled `lnk_file`, and the fix is a
    *self* grant with *both* `getattr` and `read` (#61's split applied to a
    self object).** `ls -laZ /proc/self/` printed `l??????????` for `cwd`
    and `exe`: scontext and tcontext identical. The existing self grant
    `(lnk_file (read))` covered the readlink but not the lstat. The grant
    grew to `(lnk_file (getattr read))`. The *top-level* self links
    (`/proc/self`, `/proc/mounts`) are `proc_t` (not self), needing only
    `getattr` added to the existing `proc_t:lnk_file` grant. — *`ls -laZ
    /proc/self/` in the sandbox (2026-11-12, kernel 7.2.15, enforcing);
    `selinux/apse.cil`.*

65. **`/proc/net` is a *relative* symlink (`self/net`) — the link and the
    content behind it are different types, so following it needs grants on
    *both* layers.** Fish (which readlinks `/proc/net`) produced
    `denied { read } … tcontext=…:proc_net_t:s0 tclass=lnk_file`. Following
    the link lands in the process's *own* `/proc/<pid>/net` dir (self-
    labeled `apse_app_t` by #45), whose *files* are `proc_net_t` again — so
    content needs `file (getattr open read)` on `proc_net_t` in addition to
    `lnk_file (getattr read)` on the link. Trap: fixing the link makes
    `stat /proc/net` work, but `head /proc/net/dev` is still denied — the
    content is a separate check. — *fish and `head /proc/net/dev` in the
    sandbox (2026-11-12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

66. **Top-level `/proc` entries are mostly *not* `proc_t` — each has its own
    dedicated genfs type, and `ls /proc` stats them all, so the grants are
    per-type `getattr` (and `getattr`-only is the safe bound).** The
    `/proc` root is a grab-bag: `sysctl_irq_t`, `proc_psi_t`, `proc_kmsg_t`,
    `mtrr_device_t`, `proc_kcore_t`, `proc_mdstat_t`, `system_map_t`,
    `sysctl_t` — the rest of the tree is `proc_t`. A listing only stats
    (no content read), so `getattr` alone is the right bound: deliberately
    no `open`/`read` on `proc_kcore_t` or `proc_kmsg_t`. — *`ls /proc` in
    the sandbox (2026-11-12, kernel 7.2.15, enforcing);
    `selinux/apse.cil`.*

67. **The module-store CIL reader takes *one* class per `allow` rule — the
    multi-class form is rejected at install with a terse `Bad allow rule`.**
    `(allow apse_app_t proc_type (file (getattr)) (dir (getattr)) (lnk_file
    (getattr)))` fails; the one-class-per-`allow` form installs cleanly. The
    constraint is in the reader's AST builder, not in CIL as a language: the
    classic checkpolicy pipeline emits one class per rule, so no installed
    module has ever exercised the multi-class path. A second trap: an
    unprivileged `semodule -l` fails and shows *nothing*; a load check needs
    `sudo`. — *the attribute-based /proc stat redesign (2026-11-12,
    libsepol 3.11, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

68. **A module domain's self-grants stay an *explicit* mirror of the base
    policy's own `domain` set, not `domain`-attribute membership — the
    attribute is two-sided and the *subject*-side (`domain → X`) is the one
    that matters.** The v2.25 pass rejected `typeattribute apse_app_t
    domain`. (a) The *subject*-side adds **121 active `domain → X` rules
    across 74 host types** — the escape surface: reads across the base file
    families, `setrans_t` translate, `systemd_resolved_t` `connectto`,
    `kernel_t module_request`, process probes, socket-receive against
    `unconfined_domain_type`. (b) `container_t` is a safe member because a
    *normal* sandbox gates most of that reach with the primary controls
    (mapped uids, the container runtime's own seccomp/landlock); apse has
    no such net (the app runs as its *real* uid, every primary control is
    built by apse in one process tree) — that is why the module stays the
    *independent second layer* and the explicit mirror is what the tuning
    loop audits (a denial → a grant), whereas the imported set would drift
    silently with base updates. (c) The *target*-side (851 active
    `X → domain` rules) is the *intended* host→app direction — verified live
    with zero AVCs. (d) The base process neverallows block nothing here
    (a violation is refused at `semodule -i`; joining adds none). Authoring
    traps: the `sem`/`shm` classes have **no `ioctl` permission** (a
    `Failed to resolve permission` at `semodule -i` is the detector); on a
    `fips_mode`-on box the fifo self-grant must be the
    `manage_fifo_file_perms` superset. Detector: a *module* type whose
    denial audit keeps surfacing grants the *base policy's own* users of the
    class already have — audit the attribute on *both* sides before joining;
    `domain` is the canonical case. — *the v2.25 completeness pass
    (2026-11-12, kernel 7.2.15, enforcing); a 24-point grant probe in a live
    `apse run` (zero denials, the audit `denied` baseline flat).
    *Superseded in part (2026-11-13, v2.28): the per-prot premise does not
    hold on the running 7.2.15-300.fc45 build — the A/B that dropped the
    broad `file_type:* map` grant; #71.*

69. **`id -Z` failing in the sandbox with "works only on an SELinux-enabled
    kernel" is a rootfs artifact, not a policy denial.** libselinux's
    "is the kernel SELinux-enabled" probe `statfs`es `/sys/fs/selinux` and
    expects `SELINUX_MAGIC`. The rebuilt rootfs leaves `/sys/fs` **empty**
    (fresh `/sys` tmpfs; the cgroup2 fs is not re-rooted — decisions #12/
    #20), so the probe gets `ENOENT` and `id` bails out *before ever trying
    the attr read* — which would have succeeded (zero AVCs for the whole
    run). Fix if it matters: bind the `/sys/fs/selinux` mount into the
    sandbox; the dangerous files there are root-owned with no group/other
    write, and the app is its real uid (uid 0 unmapped, #9), so DAC keeps
    them unwritable. — *diagnosed 2026-11-13 (kernel 7.2.15, enforcing,
    v2.25): `id -Z` in a confined `apse run`; the strace / `stat -f` /
    empty-audit triangle closed the chain.*

70. **SELinux attributes expand in `semodule -i` CIL mode, but this
    `sesearch` cannot see that expansion — verify attribute membership with
    a controlled exec or an AVC, never a sesearch hit/miss.** A probe module
    using the base policy's `exec_type` *attribute* in the *target* slot of
    an allow installs cleanly and the compiled policy's access vectors carry
    the full set of tagged types. A runcon exec oracle confirmed: **141/141**
    of the `/usr/bin` + `/usr/sbin` file types have `exec_type`, zero
    denials. The trap: `sesearch --allow -t <type>` against an attribute-
    valued rule returns the *raw* rule for *any* type (even `usr_t`, a
    directory type); the `-ds`/`-dt` "match attributes" flags take no
    argument (the `Errno 2` came from passing the attribute as a *positional*
    argument, which the CLI parses as a policy-file path). Supplement: for
    pure membership questions, `seinfo -a <attr> -x` lists the attribute's
    compiled member types straight from the loaded policy. Supplement
    (user-corrected): the `-ds`/`-dt` flags *do* work for the literal-
    matching direction — combined with `-s`/`-t`/`-A` they suppress
    expansion of the attribute named there, so `sesearch -ds -s domain -A -c
    filesystem` lists only rules whose source slot literally says `domain`
    (here: `base_file_type` / `base_ro_file_type` plus named types — *not*
    `non_auth_file_type`); `-dt` is the target-side mirror. That is the
    right tool for "does X grant on attribute A as written"; for the reverse
    question, `seinfo -a <attr> -x` remains the oracle. — *probe module
    `execprobe`, installed and removed the same hour; the runcon oracle is
    the reusable technique.*

71. **On kernel 7.2.15-300.fc45 the plain `mmap()` path enforces no SELinux
    file permissions — `open()` is the gate — so the v2.25/#68 per-prot
    premise (and the broad `file_type:* map` grant it justified) is dead;
    the grant is dropped (v2.28).** v2.25 modeled `mmap(2)` on the pre-7.2
    `file_mmap` hook: checked per *protection* with only the PROT_NONE case
    (`map`) ungranted. The v2.28 A/B (module reinstalled with the broad grant
    present, then absent, an identical probe run both times) shows that
    model does not hold on this kernel's running build: a probe running as
    `apse_app_t` mmaps an `etc_t` file private with all four prots; all
    succeed with **zero AVCs**, and the results are identical with and
    without the grant — the grant was inert. The source side, from the
    vanilla 7.2.15 tag: the old `file_mmap` hook is gone, replaced by
    `mmap_file` (`selinux_mmap_file` → `inode_has_perm(FILE__MAP)` +
    `file_map_prot_check`), but the tag *does* call
    `security_mmap_file` from `vm_mmap_pgoff` (the x86-64 `mmap()` path) —
    which the running build's observed behavior contradicts (a Fedora
    mm/LSM patch, or the probe not hitting the check's path, would each
    explain it). Practical upshot: file access is gated by `open()`
    (`file_permission` read/write), exactly as the per-type rules model; the
    per-type `map` grants stay (the `domain.te` shape, and they cover the
    paths the hook is wired to in the vanilla source: `mremap`, the
    backing-file check, `mprotect`); the revisit trigger for the broad grant
    is an *actual* `map` AVC. Probe trap: `vm.mmap_min_addr` (65536 on this
    box) shadows the `mmap_addr` hook — a low-address `MAP_FIXED` probe
    fails the VFS threshold check first (a zero-AVC `EPERM`), so it is a
    useless canary for that check. — *v2.28 (2026-11-13, kernel
    7.2.15-300.fc45, enforcing): the A/B behind the broad-grant drop; the
    open detail is vanilla-vs-Fedora wiring of the 7.2 `mmap_file` hook.*

72. **A plain `bind(2)` shares the dentry tree — writes on either side are
    visible through the other; "the bind hides the target" only holds when
    the target is *replaced* (a fresh tmpfs/mounted on top of the
    directory).** The task 8.10 confusion was the write going into a
    scratch subdir that had *never been bound* (a plain btrfs directory),
    not a bind snapshotting content. — *v2.30 (2026-11-13, task 8.10: the
    `/etc` sources moved from the /var/tmp scratch to
    `$XDG_RUNTIME_DIR/apse/<inst>/etc/`).*

73. **Two validation gotchas around the XDG runtime dir.** (a)
    `tempfile::TempDir` creates its dir **0755**, but
    `xdg::BaseDirectories::get_runtime_directory()` enforces the XDG spec's
    **0700** — a test that fakes `$XDG_RUNTIME_DIR` must `chmod` the dir
    0700 before spawning or the daemon exits before binding anything. (b)
    glibc's `gethostbyname` for the *local* hostname consults the nss
    `myhostname` module, which maps it to `127.0.0.1`/`::1` independently of
    `/etc/hosts`; a `files` entry on a different loopback address
    (`127.0.1.1`) would show up only through `gethostbyname_ex`/
    `getaddrinfo`. The 8.10 generated file deliberately uses `127.0.0.1`
    (the user's call), so all three paths agree. — *v2.30 (2026-11-13).*

74. **A one-shot exec context (`/proc/self/attr/exec`) protects only the
    `exec` that consumes it — grandchildren that exec later fall through to
    the domain's default transition rules, so a compiler pinned in place
    drags its own children into the app domain.** #42 pins the shim
    compiler's `cc` by writing S's own `apse_t` context into `attr/exec`,
    but `cc` vforks `collect2`/`ld` and their `exec`s come *after* the
    one-shot context is consumed — so the module's `typetransition` fires
    for them and they run as `apse_app_t` in the **host** mount view. Fix:
    two traversal-only grants, `user_home_t`/`gconf_home_t` `dir (getattr
    search)` (no `read`). — *task 8.9 tuning; `selinux/apse.cil`, the
    LESSONS #42 follow-on.*

75. **On this kernel inotify watches are mediated as `file:watch_reads` on
    the watched dir — not `watch` — and dash probes the script file it is
    about to exec with a `TCGETS` `ioctl` (a no-op on regular files, denied
    only in the audit sense).** `inotify_add_watch()` on a dir whose grant
    carries `watch` but not `watch_reads` fails `EPERM` (the AVC asks for
    `watch_reads`). The companion file-permission gap: `ioctl` on the
    state-tree file grant, for dash's `TCGETS` probe. — *task 8.9 tuning;
    `selinux/apse.cil`.*

76. **`application_exec_type` is the *dedicated* per-purpose set, not "most
    normal binaries" — the attribute's name is a trap.** On this system the
    attribute has 311 compiled members and is a *strict subset* of
    `exec_type` (1048 members). What it excludes is exactly what a real-uid
    app should never exec: init scripts, server daemons, inetd services —
    *and* the generic catch-alls `bin_t`/`shell_exec_t`/`usr_t`. So
    "attribute grant + the existing enumerated catch-all rules" is
    precisely "everything but the daemon/init dedicated types". Membership
    oracle: `seinfo -a <attr> -x` — this `sesearch` does *not* resolve
    attribute membership in rule queries. — *task 8.8 (v2.32);
    `selinux/apse.cil`.*

77. **A generic attribute-object `typetransition` is infeasible, not just
    unverified — the transition table is single-valued on (subject, objtype,
    class).** Writing `(typetransition apse_t application_exec_t process
    apse_app_t)` would expand the attribute into its 311 members and map
    *every* of them — including `xserver_exec_t`, which must keep its own
    `xserver_t` target — to `apse_app_t`, colliding with the existing
    `xserver_exec_t → xserver_t` rule at install. The app transition set
    stays enumerated (one line per dedicated-type app actually run). —
    *task 8.8 (v2.32); `selinux/apse.cil`.*

78. **On this 7.2 kernel the netlink socket classes carry *separate*
    `nlmsg_read`/`nlmsg_write` permissions — plain `read`/`write` is not
    the check for recvmsg/sendmsg.** `ip`'s RTNL round trip failed in three
    stages: `create`, `getsockname` (the distinct `getattr`), and finally
    `nlmsg_read` on `netlink_route_socket`. The companion finding that makes
    the whole grant safe: there is no `sockcreate` filetrans for
    `apse_app_t`, so a socket the app creates is born in the *creator's*
    own context — every socket operation is self-targeted and therefore
    MCS-bounded. — *task 8.8 (v2.32); `selinux/apse.cil`.*

79. **This libsepol (3.11) CIL reader does not take the TE boolean syntax —
    and selinuxfs boolean files hold two fields, not one.** `gen_bool`/`if`
    are rejected as "Unknown keyword"; the CIL forms are `(boolean NAME
    true|false)` (declaration) and `(booleanif NAME ( true
    <statements…> ))` (conditional) — the condition is the *bare* boolean
    name and the body's first child must be the *bare* `true` keyword.
    Reading side: `/sys/fs/selinux/booleans/<name>` holds `<value> <state>`
    (two fields, space-separated) — so a `s.trim() == "1"` reader misreads
    an *on* boolean as off. A confined supervisor that wants to read *its
    own module's* boolean needs explicit grants (`security_t` labelled
    selinuxfs: `apse_t` got `dir { search getattr }` and `file { open read
    getattr }`). — *task 8.7 (v2.33); `selinux/apse.cil`, `src/mcs.rs`.*

80. **A per-sandbox seccomp gate is a second stacked classic-BPF filter,
    with three sharp edges in its BPF.** (a) The X32 marker bit
    (`0x40000000`) lives in the syscall *number* field, not the arch field:
    a guard that loads `arch` and compares against the X32 bit treats
    *every* native 64-bit syscall as X32 and bricks the process — the guard
    must load `nr` and mask the bit. (b) `SECCOMP_SET_MODE_FILTER`
    requires `PR_SET_NO_NEW_PRIVS` or `CAP_SYS_ADMIN` — an unprivileged
    test child must set NNPS first or it dies inside the install. (c) Only
    *one* filter per process may use `SECCOMP_FILTER_FLAG_NEW_LISTENER` —
    nono's notify filter owns it, so the gate is a plain filter, installed
    *after* nono's (filters evaluate newest-first / LIFO). Also: JSET
    encoding convention (nono's): `jt=0, jf=1` — "taken" falls to the
    *next* instruction, "not taken" skips one. — *task 8.7 (v2.33);
    `src/sandbox/policy.rs`.*

81. **Unprivileged `mount(2)` in a self-created user+mount ns works
    *before* the first `execve` and returns EPERM *after* it (single-extent
    non-root uid map); never use `unshare(1)` for probe harnesses.**
    Decisive A/B on 7.3.3/F45: one process does `unshare` + writes the maps
    directly, then `rbind / → /` succeeds before the `execve` and the
    identical operation after `execve` into bash fails with EPERM. That is
    why `unshare(1)` (which always `exec`s its command) got EPERM on
    *every* mount. apse is immune by construction: A (the ns creator, never
    exec'd) performs all rootfs steps and B (a fork) mounts `/proc` before
    its own exec. *(Amended 2026-11-15: later probe harnesses on this same
    kernel got EINVAL on the self-bind; the harness-vs-production
    divergence is recorded as open in #84. Production apse is unaffected:
    all 42 of its `mount(2)` calls succeed.)* — *toolchain exploration;
    `docs/toolchains.md` finding #8, commit `1de378f`.*

82. **A setuid-root binary is *inert* in apse's single-extent user
    namespace — the euid grant is gated on the file owner being *mapped*,
    and the capability upgrade on `root_privileged()`.** `bprm_fill_uid`
    (`fs/exec.c:1650`) skips the euid grant unless
    `vfsuid_has_mapping(user_ns, owner)`: in the single-extent `<uid> <uid>
    1` map the owner uid 0 is unmapped, so the euid stays the real uid;
    `handle_privileged_root` (`security/commoncap.c:829`) skips the
    capability upgrade unless `root_privileged()` (also false for an
    unmapped root). The effect is a **namespace** property, not a mount
    property. Even in the worst-case nested `0→<uid>` mapping (the podman
    shape), the suid bit is **indistinguishable** from a non-suid file.
    There is no setuid path to privilege in the apse design. — *setuid-in-
    sandbox investigation (2026-11-15); 8-child probe.*

83. **On 7.3.3-300.fc45, unprivileged overlayfs works (upper+workdir,
    plain-directory lowers, both `1000:1000:1` and nested `0→1000`
    mappings) — but `lowerdir=/`, the *original* root mount of the init
    mount namespace, fails EINVAL.** The failure sits in the new mount
    subsystem's clone path (`ovl_clone_private_mount` →
    `clone_private_mount` → an ns-capability check against the mount's
    *owning* namespace): the init-ns root is owned by the init user
    namespace, which an unprivileged creator cannot satisfy. So an
    unprivileged overlay's lower must be a plain dir or a creator-owned
    mount: the toolchain store in `/var/tmp` (plain dir) is the working
    shape, and the whole-root runtime overlay must use the step-2
    self-bind as its second lower. — *toolchain / setuid investigation
    (2026-11-15); `docs/toolchains.md` §10.4.*

84. **On 7.3.3-300.fc45, legacy `mount(2)` behaves differently in probe
    harnesses than in production apse — open question; do not restructure
    `mounts.rs` on it.** A minimal probe (every unshare ordering, with and
    without `MS_REC|MS_PRIVATE`, with and without pid/cgroup ns; root and
    uid 1000) gets **EINVAL** on `mount("/", "/", MS_BIND|MS_REC)` and on
    every other bind of a host mount, while the production `apse` binary
    performs the **identical sequence** and all **42** of its `mount(2)`
    calls succeed (strace; zero `open_tree`/`move_mount`/`fsopen` — pure
    legacy API), and the app runs to a clean exit. No SELinux AVC denials
    (same result for both labels). The 7.3.3 source tarball does not match
    the running kernel's UAPI, so its `MNT_NS_INTERNAL`/`check_mnt`
    explanation may not apply. The one untested variable: production passes
    **non-NULL** `type` (`"none"`) and **non-NULL** `data` (`""`) on the
    self-bind while the probes passed NULL for both. **Do not** rewrite
    `mounts.rs` to the new mount API on the strength of the tarball
    analysis: the production path is field-verified end-to-end. Next
    diagnostic if pursued: a minimal C probe passing `("none", "")` on the
    self-bind. — *setuid-in-sandbox investigation (2026-11-15); production
    `apse run` strace vs probe harnesses.*

85. **On 3.11, a filecon carrying the `HOME_DIR` template keyword is routed
    to `file_contexts.homedirs`, not the main `file_contexts` — and
    `matchpathcon`/`restorecon` consult *both*, so it is fully
    effective.** On `semodule -i`, libsemanage runs `semanage_split_fc`
    over the CIL's `cil_filecons_to_string` output: any line beginning with
    `HOME_DIR`/`HOME_ROOT`/`ROLE`/`USER` goes to the separate
    `file_contexts.homedirs` template, which `genhomedircon` expands into
    `file_contexts.homedirs.bin`. The 3.11 file backend opens *both* `.bin`
    files and descends the path tree to the **deepest literal match** — so
    the deeper `…/state/apse(/.*)?` beats the gnome module's broader
    `HOME_DIR/\.local(/.*)?` → `gconf_home_t`. Verified: `restorecon -nvR
    ~/.local/state/apse/` is silent, `matchpathcon` on a deep file returns
    `apse_state_t`, and the sibling `~/.local/state/other` still resolves to
    `gconf_home_t`. A *custom* `XDG_STATE_HOME` outside `~/.local/state` is
    unreachable by any filecon — S's relabel walk self-heals that case.
    — *state-tree filecon investigation (2026-11-15); the 3.11
    libsemanage/libselinux sources (`semanage_split_fc`, `matchpathcon`)
    and the installed module's CIL.*

86. **On this kernel, a `PF_UNIX` socket's bound inode carries the
    *creator's* label, not the parent dir's — a filetrans on the socket's
    home dir does not touch the socket file.** `selinux_sock_graft`
    (`security/selinux/hooks.c`, 7.2.15) runs at `bind(2)`: for `PF_UNIX`
    (and IPv4/6) it copies the socket *object's* SID — the creator's — onto
    the bound inode, and the socket object keeps that SID for its life; the
    inode's label therefore tracks the creator's domain, never the parent
    dir's filetrans. Decision #47 (`apse_xsocket_t`) is built on it: the
    named filetrans labels the `x/` subdir (born the module's type), and the
    no-rule default makes the MIT auth file — created under it by
    `xserver_t` — inherit the label, but the X socket file is `apse_t` (its
    creator), so `xserver_t`, which holds the listener purely by fd and
    never opens it by path, needs no `sock_file`/`unix_stream_socket` grant
    on the new type at all — the three pre-change `xserver_t → user_tmp_t`
    base→base rules collapse into one module→module grant. Corollaries: the
    self-heal of a stale pre-filetrans `x/` is remove+recreate, not a
    setxattr relabel (a relabel would need `relabelto`, which the module
    deliberately does not grant), and the static-half filecon
    (`/run/user/%{USERID}/…` → the type; `%{USERID}` → `[0-9]+` in 3.11's
    `file_contexts.homedirs`) registers the *expected* label for
    `matchpathcon`/`restorecon`, which the filetrans alone never does. —
    *`apse_xsocket_t` design (2026-11-15, decision #47); the 7.2.15 kernel
    source (`selinux_sock_graft`) and the installed 3.11 filecon table.*

87. **nix 0.32 gated `getuid`/`getgid`/`getgroups` behind a new `user`
    feature (they were ungated in 0.31).** The other 0.32 breaking
    changes — `sys::socket::accept`/`accept4` returning `OwnedFd` and
    taking `AsFd`, `fcntl::vmsplice` going `unsafe` — are unused here,
    so only the feature list needed `user` added. Note the graph now
    carries *two* nix versions (0.32 for apse, 0.31.x for nono's linux
    target dep) — expected, not a conflict. — *nix 0.32.0 changelog
    (`user` feature gate, `accept` → `OwnedFd`).*

88. **An exec that changes the SID checks `noatsecure`, `rlimitinh`
    and `siginh` — not just `transition`/`entrypoint` (7.2.15).**
    Writing an *explicit* exec context skips the `type_transition`
    table (the kernel takes the pending `exec_sid` as the new SID
    directly), and that was all the first 8.6 module rule granted —
    but the new-SID branch of the exec check does further
    `avc_has_perm` calls: `noatsecure` (a denial flips the exec into
    secure mode) and `rlimitinh`/`siginh` (the inherited rlimit and
    signal state). Reading the source found the visible `noatsecure`
    check only; the audit trail of the first `--no-selinux` run
    (2026-11-18, all three denied, non-fatal) is what enumerated the
    set. The MCS self-narrowing re-exec already carries the trio via
    the `apse_t` self-grant — when a new SID-changing exec path is
    added to the module, grant it there too; when in doubt, trust
    `ausearch -m avc` over a source reading. — *the first
    `--no-selinux` run's audit trail (enforcing, 7.2.15),
    `security/selinux/hooks.c`.*

89. **User-visible text that embeds a CLI invocation is a second CLI
    surface.** The broker's consent-notification body carries a
    ready-made reply command; the 7.1 subcommand rename (the branch-era
    global `--decide` flag → the `decide` subcommand) rewrote the
    units and the docs but not that body, so the one command a user
    copy-pastes out of the *only* documented channel no longer parsed.
    The fix pins the body in a unit-tested `prompt_body`. When a CLI
    grammar changes, grep the tree — notification bodies included —
    for embedded invocations. — *the 7.1 rename's leftover
    (2026-11-18); the same class as #49 (baked header lettering).*
