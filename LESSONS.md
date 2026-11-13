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
   one-element path.** The fd-misrouting bug was invisible to every existing
   test because they all used exactly one fd, where `take == len` made the
   wrong `split_off` call accidentally correct. The bug only surfaced with two
   or more fds in a datagram. `VecDeque::split_off(n)` keeps `0..n` and
   *returns* `n..len`; to consume the first N in arrival order the primitive
   is `drain(0..take)`. — *`docs/postmortems/fd-swap-fix-plan.md` §1, §5;
   commit `88d237e`.*

2. **In a security-sensitive path, name the category of the bug before
   fixing or reporting it.** The fd mispairing sat in the clipboard path but
   was a *data-integrity* bug, not a *security* regression: the gate's
   forward/drop decision keys on the object id + origin, never on the fd
   itself. Determining and stating the category up front is what keeps the
   commit message and any disclosure framed correctly. — *post-mortem §4.*

3. **Read the load-bearing lines at the actual line numbers before trusting a
   handoff doc.** The handoff plan was accurate, but the confidence in the fix
   came from reading the real `split_off` call and the `wire::parse_message`
   `pop_front` contract, not from the document alone. Treat a handoff or
   post-mortem as a starting point; verify the lines the fix depends on.
   — *post-mortem §2, §9.*

10. **Anchor a rate-limit window on the last *emitted* event, not on every
    suppressed one.** If every event — including the suppressed ones — reset
    the window, a continuous stream would suppress itself forever: the first
    event fires, and each subsequent event keeps the window fresh so nothing
    ever fires again. Anchoring on the emission instead gives a steady stream
    exactly one event per window, and re-notifies as soon as the stream pauses
    for a window. The copy-out notification rate limit
    (`ClipboardGate::note_copy_out`) does this; the audit log (one record per
    event, no limit) is what keeps the suppressed ones on the record.
    — *commit `3931f52` (the Phase 6 follow-up).*

11. **A daemon that serves a long-lived control channel plus many
    short-lived clients: run the control channel in the main thread and
    the client work on spawned threads — never the reverse.** The
    broker's old per-prompt design parked the *main* loop in the
    30-second consent wait, so a second pending prompt was
    structurally impossible (the accept loop never even got to run).
    The fix inverted it: the main thread owns the session decision
    socket on a `poll(2)` over both listeners (a short read timeout
    bounds a misbehaving decider), and each connection — including a
    prompt waiting for the user — parks on a per-prompt condvar in its
    own thread, so the decision wakes exactly the waiting thread.
    Keeping the decision *and* the queue removal under one lock is
    what makes a double-decide a clean `unknown-prompt` instead of a
    double resolution. — *commits `6365ae5`, `b186c13` (the session
    decision socket).*

## Writing tests

4. **Write the test, watch it fail, then fix (red → green).** Don't add a
   regression test and immediately run it green. First confirm it fails on the
   current buggy code with the *exact* expected symptom (here: the two fds
   arriving swapped — `HTML-SENTINEL` vs `PLAIN-SENTINEL`), then apply the fix
   and confirm it passes. A test that never fails proves it catches nothing.
   — *post-mortem §6–7.*

5. **Prove batching is structural, not a race, before calling a test
   "deterministic".** A test that relies on two messages landing in one
   datagram is trustworthy only if you've traced *why* they must batch: here
   `wayland-client::EventQueue::blocking_dispatch` drains all pending events
   before flushing, so two requests issued in one dispatch pass always
   coalesce into one `sendmsg`. "It ran 10/10" is not the same as "it must".
   Verify the mechanism in the library code, then trust it. — *post-mortem
   §3.*

6. **Reuse the existing harness; don't reinvent the scaffolding.** The
   regression test reused the existing clipboard harness (`Srv2` /
   `OfferState`) and only added a second data offer plus a client issuing two
   back-to-back `receive` calls. Leveraging proven scaffolding keeps the new
   test small, realistic, and focused on the actual defect. — *post-mortem
   §6.*

## Toolchain and scope

7. **Establish the toolchain baseline before blaming your own diff.** The 44
   `cargo fmt --check` hunks (and a couple of clippy lints) across
   `objects.rs`, `policy.rs`, `wire.rs`, and `phase0_interface_tables.rs` were
   *pre-existing* rustfmt 1.10.0 drift, not caused by the change. When a
   gate fails, determine the baseline — which files, which tool version —
   before attributing it to your edits, and fix only what is in your scope.
   (The pre-existing drift is a separate, deferred cleanup.)

8. **Keep the diff to the defect.** The fix touched exactly `forward()` in
   `src/proxy/mod.rs` and the new test — never the gate, audit, broker, or the
   wire codec, even where adjacent code looked improvable. Related defects
   found in the same review (e.g. the `start_drag` pending-latch, post-mortem
   §10) get their own `TASKS.md` entry and their own commit; they are never
   bundled into an unrelated fix.

## Gotchas

9. **Wayland macros live at `impl` level, not inside `fn event`.** Placing
   `event_created_child!` inside the body of `fn event` produces a confusing
   *runtime* panic — "Missing event_created_child specialization for event
   opcode 0 of `wl_data_device`" — deep in `wayland-client`'s event queue,
   far from the real cause. The macro must be a sibling of `fn event`, inside
   the `impl`. — *`tests/proxy_integration.rs` (Srv4).*

12. **In a mode-based binary, global clap `required*` attributes break the
    modes that don't need the argument.** `--listen` had
    `required_unless_present = "socket_activation"`, so the `--decide`
    one-shot (which never binds a socket) demanded a fake listen path.
    Keep such arguments optional at parse time and enforce presence in
    `validate()` for the specific modes that bind. — *commit `26f54c6`.*

13. **Don't re-exec a socket-activated process to "reload" it.** The
    activated fd may carry `FD_CLOEXEC` (in which case `execve` closes
    it, and the `LISTEN_*` env you restore points at a dead number), and
    where the security context is stamped *on* that very fd
    (tag-and-park), the compositor may refuse to re-stamp it. In
    `apse` the SIGHUP rebuild therefore branches on how the listener
    was obtained: `--listen` re-execs in place (the freed path is
    re-bound and re-tagged); a socket-activated run exits cleanly and
    lets `Restart=always` re-pass a fresh fd. — *commits `e390b32`,
    `6923ea5`.*

14. **`CString::new` and `CString::from_vec_with_nul` have opposite
    conventions about the trailing NUL.** `new` treats a trailing NUL
    as an *interior* NUL and rejects it; `from_vec_with_nul` requires
    the last byte to already be NUL and never appends one. To convert
    NUL-free bytes (argv elements, `NAME=value` pairs for `execve`),
    append the NUL first, then call `from_vec_with_nul`. — *`src/proxy/mod.rs`
    (`osstring_bytes_to_cstring`).*

15. **A forked child must inherit no live OS threads — from any
    runtime, global *or* local.** Two hazards, both `fork(2)`-related:
    (a) `zbus::blocking` (v5) drives futures on a process-global `tokio`
    runtime in a `static OnceLock`; in a forked child the `OnceLock`
    still reports it built while its worker threads are gone, so
    `block_on` hangs forever and *silently*. (b) Even a fresh **local**
    `new_multi_thread()` runtime is unsafe here: `attach_scope` runs in
    `S` *before* the supervisor forks `A`, and dropping a multi-thread
    `Runtime` does **not** join its workers, so they linger for a few ms
    across the fork. The child inherits them and `std`'s process-global
    `thread_info` mutex (locked on every thread start by the
    stack-overflow guard) is left owned by a vanished thread, so the
    first thread the child creates deadlocks on it — the whole binary
    hangs, the forking test's `SANDBOX_LOCK` never released. The fix:
    drive the *async* API on a **current-thread** runtime (no background
    workers → nothing lingers). Rule of thumb: anything that may run in
    or near a forked child must be fork-safe — no live OS threads. —
    *the clipboard-branch merge (Phase 7); `src/systemd.rs`
    (`with_local_runtime`), `src/sandbox/mod.rs` §5.4.*

16. **Env-mutating tests must run single-threaded; a lock only
    against *other* `setenv` callers is not enough.**
    `std::env::set_var`/`remove_var` are C `setenv`/`unsetenv` and are
    undefined behaviour when *any* other thread reads the environment
    concurrently — not just another `with_env`, but plain readers like
    `temp_dir`, xdg, and clap `getenv`. The socket-activation tests
    (which must set `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES` for
    sd-notify to see) race such readers under a parallel run: the two
    separate `env::var` reads inside sd-notify catch a corrupted env
    block between them and mis-report a fd-name count mismatch, so
    `listen_fds_with_names_and_unset_env()` returns `Err` and one test
    fails at random. `ENV_LOCK` serialises `with_env` against itself but
    cannot stop unrelated readers. The fix is `cargo test --
    --test-threads=1` (wired into CI): it costs ~nothing, since the
    suite is dominated by the `SANDBOX_LOCK`-serialised sandbox tests.

17. **A queue filled by concurrent threads is ordered by a sequence
    stamped at the sequential entry point, never by lock order.**
    The broker's prompts were registered by per-connection threads
    (`add_prompt` hands out ids under the queue lock), so *which*
    thread grabbed the lock first decided the order — not which
    connection arrived first — and the
    `multi_prompt_session_is_listed_and_decided` integration test
    flaked whenever the second app's thread won the race. Fixed by
    stamping each connection with a monotonic sequence in the
    broker's `poll(2)` accept loop (the only sequential point) and
    ordering the queue by `(seq, id)`; ids stay unique (so two
    prompts from one connection cannot collide in the order), and
    both the listing and the untargeted decide derive from the
    sequence. Pre-existing from the clipboard branch; its
    integration tests build the queue directly, so nothing exercised
    the thread-race path until the desktop e2e found the sibling
    allowlist bug and the flake was re-run.

18. **When a spawner passes an fd to a child, the argv is half the
    contract — and its absence fails silently.** Phase 7.2's
    socketpair rewrite handed `xdg-dbus-proxy` its lifetime fd on fd 3
    but dropped the *`--fd=3` flag* from the argv: the proxy (told
    nothing) never wrote its sync byte, so the sidecar parked forever
    in its one-byte readiness `read`, and a SIGKILL'd sidecar left the
    proxy alive. Nothing in GLib or the kernel was wrong — the bug was
    invisible in every "it works" smoke test except the SIGKILL one.
    Two tools found it fast: `gdb`-dumping the child's *ppoll
    arguments* (fd 3 absent from the array in the broken run,
    present — with `events=0` — in a control run) and an
    `LD_PRELOAD` ppoll tracer. Related, verified on GLib 2.90: that
    `g_io_add_watch(G_IO_ERR|G_IO_HUP)` is polled with *zero*
    requested events (GLib masks those bits out — an IRIX-era
    workaround) and fires only because the kernel reports `POLLHUP` in
    `revents` even when unrequested; and the fd must be **non**-CLOEXEC
    to survive `execve` (it *closes* CLOEXEC descriptors — the inverse
    of the reflex).

19. **The `-listenfd` contract: the *spawner* must `listen(2)` before the
    handoff.** Xwayland's `-listenfd` path (libXtrans `SocketReopen`)
    adopts the given fd *as-is* and never calls `listen` itself — only
    the create-from-scratch path (`SocketUNIXCreate`) does. Hand over
    an unlistened socket and the server's `accept(2)` fails `EINVAL`
    on every readiness wake: an infinite `accept() failed` flood at
    100% CPU (it also filled our `/tmp` quota with its stderr). sway's
    own spawn is the model: it `listen`s first. The bug was invisible
    in every "it starts" smoke test; an `LD_PRELOAD` `accept` tracer
    (fd number + errno, count-capped) pinned it to fd 4 / `EINVAL` in
    one run.

20. **The kernel clears `PR_SET_PDEATHSIG` on any exec that changes
    the process's *security credentials* — not just setuid, and not
    just `AT_SECURE`.** On this (SELinux-enforcing) machine `Xwayland`
    execs into the `xserver_t` domain; the transition changes
    `cred->security` and the kernel's
    `security_bprm_committing_creds` clears the death signal — while
    `AT_SECURE` stays *unset* (absent from the auxv), so glibc still
    honors `LD_PRELOAD` there. The fix: a 3-line `LD_PRELOAD` shim
    (compiled on demand into the per-instance runtime dir) whose
    constructor re-sets `PR_SET_PDEATHSIG(SIGTERM)` *after* the
    transition — verified: a SIGKILL'd satellite's Xwayland now dies.
    The re-set is a harmless no-op where nothing was cleared. Related
    findings from the same investigation: Xwayland's `-once` flag is
    *XDMCP-session* semantics (terminate on XDMCP retransmission
    timeout) and a no-op for a non-XDMCP rootless Xwayland — it does
    **not** exit when the last X client disconnects; and given
    `-listenfd`, Xwayland does **not** create the conventional
    `/tmp/.X11-unix/X<N>` (the live `X0` on this host was a stale
    leftover of a dead instance, not sway's bind). — *the Phase 7.3
    verification; `src/xwayland.rs` (`ensure_shim`), decision #37.*

21. **checkpolicy 3.11 (Fedora 45 "userspace 3.11"): module compilation is
   `checkmodule`, not `checkpolicy`** (which builds the base policy; its `-c`
   takes a *version number*, not a policy.conf file). A module `.te` must
   start with `module <name> <ver>;` and carry a `require { ... }` block —
   both hard errors without them; `require` takes one identifier per `type`
   line and classes with the used permissions in braces; the module policy
   version tops out at 24 (just omit `-c`); and base *type attributes*
   referenced in rules (e.g. `file_type`) are re-declared in the module and
   merge by name at load. — *the phase 8.2 module; `selinux/`.*

22. **Build a capability set against paths that exist *where the set is
   built*.** S (on the host) builds the supervisor's `CapabilitySet` against
   the *in-sandbox* instance-dir path (`/run/user/<uid>/apse/<inst>`, decision
   #28) so it can match the paths the app presents to its trapped syscalls —
   but nono's `allow_path` validates existence at build time, and that path
   exists on the host only when the session XDG *is* `/run/user/<uid>`. With a
   divergent XDG (e.g. a test harness redirecting `XDG_RUNTIME_DIR` to a temp
   dir) S's build fails, the supervisor disables itself *silently*, and every
   syscall B's filter traps — including the dynamic loader's `openat` — dies
   with ENOSYS (the closed listener's default reply). The Phase 8.4 suite pins
   the standard-XDG topology and skips otherwise; making the divergent-XDG
   case work (build against the host path, translate at match time) is a
   product change, not a test one. — *`tests/sandbox_integration.rs`
   (`session_xdg`), decision #28.*

23. **Podman is not one SELinux domain — it is two, and they map onto apse's
   two sides.** `crun` is labeled `container_runtime_exec_t` and execs (from
   `unconfined_t`) into `container_runtime_t`; the in-container payload is
   `container_t`, reached by *setexecfilecon* (the policy allows `process {
   dyntransition transition }` from `unconfined_domain_type` to
   `container_domain` — there is **no** file `type_transition` into
   `container_t` anywhere). The permissive probe (2026-10-28) ran apse in
   both: the S/A runtime side as `container_runtime_t` produced **zero genuine
   denials** (the rootfs-rebuild `mounton`s over host dirs, fresh
   `/dev`+`/proc` mounts, cgroup scope create/enter, session-bus dbus, the
   transient-scope `system:start` — all covered, because crun does exactly
   this work), including the full `--proxy` chain into live sway; the app side
   as `container_t` also ran clean. Two durable facts: (a) apse's rebuilt
   rootfs gets `container_file_t` for free — the fresh `seclabel` tmpfs mounts
   inherit the mounting process' exec label (podman's own rootfs mechanism),
   so an app tree running in a container-domain type needs almost no policy;
   (b) the in-sandbox EACCESes on unix-socket `bind` and cgroup writes are
   nono's (landlock/seccomp), not SELinux — identical in unconfined runs, no
   `avc` logged for them. The one real policy lever for a `container_t`-family
   apse: `container_manage_cgroup` (off by default) gates the cgroup-scope
   writes; the rest of the runtime side is bool-free. — *the container-selinux
   probe (permissive); PLAN.md 8.2, `selinux/`.*

24. **`semodule -i file.cil` *is* a valid install path on this toolchain
   (Fedora 45, policycoreutils 3.11) — the CIL reader lives in libsepol, not
   in the checkpolicy CLI.** Verified with a test `.cil`: it installed,
   committed, and its rules appear in the live policy (libsemanage calls
   libsepol's `cil_db_init`/`cil_add_file`). The earlier "no CIL path"
   conclusion tested the wrong tool: the checkpolicy binary has no CIL input
   mode in this build (a `.cil` fed to it parses as policy.conf and fails;
   even the live policy needs `-b`, plus `-M` since it is MLS). So install can
   be a plain `sudo semodule -i apse.cil` — no checkmodule, no
   semodule_package — with `.te` → checkmodule → `semodule -i .pp` as the
   classic alternative; the CIL path resolves against the *live* policy's
   class tables, the same tables the kernel enforces (see #26 for what that
   catches). Meta-lesson: verify against the actual tool on the machine, not
   the upstream source tree. Two probe-fed gotchas stand: (a) `mounton` is
   checked on *file* objects for bind-mounts (fresh-/dev node builds); it is a
   member of the policy's `file` *common* set (the module's `require` block
   lists it on `file` explicitly, which is legal — checkpolicy's table has
   it), so it works in both install paths; (b) on Fedora 45 the *user* session
   bus is dbus-broker as `unconfined_dbusd_t` with `/run/user/<uid>/bus`
   labeled `session_dbusd_tmp_t` — not the classic `session_dbusd_t` the stock
   `dbus_session_bus_client` inlines. — *the CIL verification + module rework;
   `selinux/`.*

25. **The 3.11 module store is CIL-based, so the CIL reader is the universal
   install gatekeeper — and it validates against the *live* policy, not
   checkpolicy's tables.** Every `semodule -i` (even a `.pp`) converts to CIL
   at commit time and re-parses it with libsepol's CIL reader
   (`kernel_to_cil.c` → `cil_add_file`/`cil_compile`/`cil_build_policydb`), so
   the reader's strictness sets the bar for *all* installs: (a) a CIL file has
   **no** `(module …)` header — that is a checkpolicy *output* convention;
   bare `(type …)`/`(allow …)`/`(typeattributeset …)` statements are the
   format. (b) the resolver validates **every** symbol and **every (class,
   permission) pair** against the live policy's class table (class-specific ∪
   its `common`) — so permissions that *compile* under checkmodule can fail at
   install: `setsockopt` (the policy's socket common is `getopt`/`setopt`) and
   `node:name_bind` (the policy's `node` class is only the network set). The
   table to check against: the live dump `checkpolicy -b -M -C
   /sys/fs/selinux/policy` or the policy source's
   `policy/flask/access_vectors`. (c) the `.pp`→CIL store writer serializes an
   *unresolved* `gen_context(...)` filecon verbatim (the classic linker
   resolves it; the writer skips that) → "Bad filecon declaration" at commit.
   Preferred fix: **embed `(filecon …)` in the module CIL** — the 3.11 reader
   handles it natively (`semodule export` re-emits it byte-for-byte; `semodule
   -r` removes the label again). Two gotchas: this libsepol CIL lexer has **no
   comment rule** (grep the filecon lines out of the source file rather than
   appending it verbatim), and the file stays plain `s0` — the per-instance
   MCS category is applied to the *process* (the self-narrowing re-exec),
   never to the file. — *the CIL install debug; `selinux/`.*

26. **`/proc/self/attr/exec` is consumed by the next exec, so a "preserve
   state across re-exec" helper must not clobber a pending write.** The MCS
   self-narrowing writes the exec context and then re-execs through a shared
   re-exec helper; that helper's own range-preservation write (re-writing the
   *current* label) would have silently overwritten the just-written target
   context, sending the process back to `s0` and re-narrowing — an infinite
   loop. The fix reads the exec attribute first and skips when an explicit
   context is already pending (`mcs::preserve_range`). Related mechanics:
   setting the exec context to the *same type* (only the range changes) still
   needs `dyntransition` on the (type, type) pair — for self-narrowing that is
   the *self* allow, easy to miss; and a range is carried by fork into
   children (a process takes its creator's *full* range), so narrowing once
   before the first fork/bind is all it takes for the *process* side — but
   note new *objects* do **not** carry the creator's range; they take the
   parent's low level (`s0`) via `default_range … target low` (see #29). —
   *the MCS wiring; `src/mcs.rs`.*

27. **`checkmodule -C` (3.11) writes `typetransition` with the raw `.te` class
   — and the kernel's bprm lookup consumes only `process`.** The classic
   checkpolicy pipeline turns `type_transition src filetype:file target` into
   *both* a file-class and a process-class avtab entry (the file/process
   transition duality); `checkmodule -C` writes only the literal class from
   the source, so its `(typetransition unconfined_t apse_exec_t file apse_t)`
   compiled and installed fine but never fired — no AVC, no error, the process
   just kept the parent type. The kernel's bprm transition lookup keys on
   class `process`. Fix: hand-written CIL spelling `(typetransition src type
   process target)`. Recognize it by the symptom: a module that installs, the
   file relabels correctly (`restorecon` works, the binary carries the exec
   type), yet the process never changes type. — *the transition-not-firing
   debug; `selinux/apse.cil`.*

28. **A process context is *valid* only when its role is associated with its
   type — and `setprocattr` enforces that with a silent `EINVAL`.**
   `context_is_valid` (libsepol/src/context.c) checks role→type (ebitmap),
   user→role, and the range inside the user's exp-range; the
   `/proc/self/attr/exec` write rejects an invalid context with EINVAL — *not*
   an AVC (a validity check, not an access check). A new module type gets only
   `(roletype object_r TYPE)` from the classic pipeline, but a shell-spawned
   process inherits `unconfined_r`, so `unconfined_u:unconfined_r:apse_t:…`
   was invalid: the MCS narrowing write failed, apse degraded to a full-range
   run, and `audit2allow -C` rejected every record in those contexts ("invalid
   security context" ×500) — a denial log that could not even be machine-read.
   Fix: `(roletype unconfined_r apse_t)` / `(… apse_app_t)` — the
   container-selinux convention (associate the *spawner's* role: `system_r`
   for daemons, `unconfined_r` for shell children). Fast oracle before wiring
   such a mechanism: `runcon user:role:type:level /bin/true`. Second half of
   the same lesson: adding the types to the base `mcs_constrained_type`
   attribute is what makes MCS categories *bind* — the base mlsconstrain (`h1
   dom h2 or t1 != mcs_constrained_type`) blocks **processes** across
   categories (a `cN` subject may signal/ptrace/transition only a `cN` process
   — a single category is incomparable with any other), but it does **not**
   isolate *files/dirs* across instances, because those objects are all
   created at `s0` (see #29) and any `cN` dominates plain `s0`, so every apse
   subject may access them; the socket/`fd` classes are not constrained at
   all, so a shared daemon still serves per-category clients. — *the MCS
   no-narrowing debug; `selinux/apse.cil`, `src/mcs.rs`.*

29. **New objects take the *parent's* low level, not the creator's range — so
   under an `s0` parent, files/dirs/sockets are always `s0`, and there is *no*
   cross-instance object isolation via MCS.** The live targeted policy sets
   `default_range dir target low`, `default_range file target low` and
   `default_range sock_file target low`; in the kernel's `mls_compute_sid`
   (`security/selinux/ss/mls.c`) the `AVTAB_TRANSITION` path for those classes
   hits `DEFAULT_TARGET_LOW` → `mls_context_cpy_low(newcontext, tcontext)`, so
   a fresh object copies the **parent directory's** low level, not the
   creating process's range. Only classes with *no* `default_range` (process,
   `unix_stream_socket`, …) fall through to `AVTAB_CHANGE`, where a
   process/socket gets the creator's **full** range (`mls_context_cpy`) and
   other classes get its low. Consequence for apse: `/run/user/<uid>` is `s0`,
   so everything an instance creates beneath it — the instance dir, the build
   scratch, the per-instance sockets — is `s0` regardless of the creator's
   `cN`; any `cN` subject dominates plain `s0` (`h1 dom h2` passes), so
   *every* instance and the `s0` broker may read and write any of them. There
   is **no** file/dir-level isolation between instances, and the earlier "the
   first creator pins the session dir to `cN`" caveat was built on the false
   premise that objects carry the creator's range: the session dir is always
   `s0`, there is no race to win and no pre-creating needed. What the MCS
   layer *does* isolate is the **process** level (a process keeps its `cN`;
   the base mlsconstrain lets only a same-`cN` subject
   signal/ptrace/transition it — a single category is incomparable with
   another, which is *stronger* than podman's `cNNN,cMMM` multi-category
   model); object separation comes from the namespaces + landlock rootfs, not
   SELinux. The enforcing-mode tuning loop is still the oracle for *allow*
   gaps; a record that fails an MLS *constrain* (as opposed to a plain allow)
   carries `mls=1`. — *the default_range investigation; `src/mcs.rs`,
   `selinux/README.md`, kernel `security/selinux/ss/mls.c`.*

30. **The kernel NUL-terminates the selinuxfs attr strings, and `str::trim`
   will not strip that — a string-equality re-exec guard read from
   `/proc/self/attr/current` becomes an infinite loop.** `read_to_string`
   returns `user:role:type:range\0`; `trim` only strips Unicode whitespace, so
   the parsed range came back as `s0\0` (later `s0:cN\0`), the `range ==
   target` loop guard in the one-time self re-exec never matched, and apse
   re-execed itself ~260k times in a single strace session (it "worked" — each
   re-exec re-narrowed — but never settled). Fix: truncate at the first NUL
   before parsing (`mcs::parse_label`). A second, related canonical-form trap
   in the same guard: `mls_sid_to_context` *collapses a low==high range to a
   single level*, so a narrowed `s0-s0:cN` reads back as `s0:cN` — the guard's
   target must be written in that single-level form or it never matches
   either. Two different causes, one symptom (a MCS re-exec that never
   terminates); the strace line count is the detector. — *the 260k-execve
   incident; `src/mcs.rs`.*

31. **`std::fs::write` on `/proc/self/attr/exec` carries `O_CREAT`, and on a
   fresh in-sandbox procfs that first open runs a `may_o_create` probe that
   SELinux answers with an `add_name` denial on the `attr/` directory.**
   `std::fs::write` opens `O_CREAT|O_TRUNC`; on a just-mounted procfs
   `attr/exec` resolves as a first-open race (negative dentry), so
   `lookup_open` runs `may_o_create` (namei.c) —
   `inode_permission(MAY_WRITE|MAY_EXEC)` on the parent `attr/` dir plus
   `security_path_mknod` → `may_create` (`DIR__ADD_NAME|DIR__SEARCH`,
   `FILE__CREATE`, `FILESYSTEM__ASSOCIATE`). Non-fatal (the kernel clears
   `O_CREAT` and re-resolves, the open still succeeds) but it logs a denial
   every run — and granting the full chain does *not* make it work, because
   the open then proceeds to `i_op->create`, which the procfs attr dir has no
   handler for (`-EACCES`). The real fix is to not ask to create:
   `OpenOptions::write(true).truncate(true)` (no `O_CREAT`) hits only the
   file's own permissions, which the module grants. — *the attr/exec O_CREAT
   probe; `src/mcs.rs`, `selinux/apse.cil`.*

32. **A confined app that runs shell *pipelines* needs a *self*-`fifo_file`
   rule — intra-app pipes carry the creator's type, so they are the app's own
   context, not `unconfined_t`'s.** `sh -c 'a | b'` creates a pipe; the fifo
   is labeled with the creating process's type (`apse_app_t`), so the
   pipeline's `fstat` (sh → `getattr`), write (`a`), and read (`b`) are all
   `apse_app_t → apse_app_t fifo_file` checks. Granting only the *external*
   pipe rule (`apse_app_t unconfined_t fifo_file`, the host shell's pipes
   handed across exec) left every intra-app pipeline `EACCES`-denied — the
   "echo + cat + ls" test never exercised a pipe, so the gap was invisible
   until a `cat … | head` run logged four self-fifo denials. Fix: `(allow
   apse_app_t apse_app_t (fifo_file (read write getattr)))`, mirroring the
   `apse_t` self-fifo rule. General form: any per-type self-object rule set
   (the app's own dirs/files/sockets) must be checked against the *app* type,
   not just the host type, or the app's internal IPC silently fails. — *the
   intra-app pipe gap; `selinux/apse.cil`.*

33. **`signull` (kill 0) is a process permission this kernel's base policy
   does *not* mlsconstrain — and a module CIL can't add one, so the gap can't
   be closed at the module level.** The process class splits the classic
   `signal` into `signull` (kill 0), `sigkill` and `signal`; the base targeted
   mlsconstrain constrains
   `ptrace`/`signal`/`sigkill`/`sigstop`/`transition`/`dyntransition` — but
   **not** `signull`. So a `signull` *allow* grant is unconstrained by MCS:
   any `cN` apse subject may kill -0 any apse process, including another
   instance's `cM` (no `h1 dom h2` gate on that permission). It can't be fixed
   in the module: libsepol's CIL reader rejects `mlsconstrain` in a module CIL
   (`"Bad constrain declaration"` at `semodule -i`), and a module can only add
   *type-based* `constrain` (no range/level terms) — so the base `h1 dom h2`
   expression cannot be mirrored for it. The `signull` grant is needed anyway
   for `terminate_app`'s kill -0 liveness probe (`apse_t → apse_app_t`) and
   strace-style tools; the cost is that the probe is not category-scoped.
   Practical impact is minimal (kill -0 only reveals existence/permission,
   which `/proc` already does) — a documented limitation, not a fix. Detecting
   it: a kill -0 you expected to be category-scoped succeeds *across*
   instances, and the audit shows **no** denial (there is no constraint to
   fail) — unlike `signal`/`sigkill`, which *are* constrained and log `mls=1`
   on a cross-category attempt. — *the signull investigation;
   `selinux/apse.cil`, `src/sandbox/mod.rs` (`terminate_app`).*

34. **A `stat`-based existence check conflates *absent* with *inaccessible* —
   and `Path::is_file()` is exactly that check, so a SELinux denial on the
   stat silently degrades the profile lookup.** `profile::load` gates on
   `Path::is_file()` (a `stat`/`metadata` call) before reading
   `~/.config/apse/apps/<app-id>.toml`, and falls back to the builtin/ad-hoc
   profile when it is false. Under SELinux a *denied* `getattr` on the file —
   or `search` on any ancestor (the confined `apse_t` reader needs
   `user_home_t`/`config_home_t` `dir search` plus `config_home_t file
   (getattr open read)`) — makes `is_file()` return false *exactly the same
   way* as the file genuinely not existing. The fallback is **silent** (no
   error, no warning), so the visible effect is a sandbox that runs with the
   *wrong effective configuration*: the user's `gpu = false` and its
   `XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY` env never apply, the session env leaks
   into the app, and nothing in the logs points at the cause. Detection: the
   app *works* but its effective config disagrees with the profile file; the
   discriminator is `ausearch` for denials against the profile path (they look
   like ordinary file denials — nothing marks them as hitting an existence
   probe) or, if you suspect this class, `stat`-ing the same path from the
   same confined context. Defense: distinguish `NotFound` from every other
   `metadata` error (fail or at least warn on the rest), and grant the
   confined reader the full read chain up to the file. — *the
   profile-not-applied debug; `src/profile/mod.rs`, `selinux/apse.cil`.*

35. **Partial or *wrong-object* grants silently degrade: the permission check
   can pass everywhere you look while the consumer still loses the capability
   — a symlink carries the label of the fs it sits on, and `open` is not
   `read` on a directory.** Two instances from the enforcing-mode tuning, one
   general class: *the audit records the denials you fix, but the failure is
   only visible in the consumer's behavior, and the record points at the wrong
   object.* (a) **The fresh-tmpfs symlink label trap:** the sandbox's
   `/dev/ptmx` is a relative symlink into the fresh devpts instance (devtmpfs
   style, step 5 of the rootfs build); the symlink is *on* the fresh tmpfs
   `/dev`, so it carries the tmpfs's **default** label (`tmpfs_t`), not the
   `ptmx_t` of what it points at. Following it is `lnk_file:read` against
   `tmpfs_t` — grants on the target type do nothing until the symlink's *own*
   type is granted. (b) **`open` vs `read` on a directory:** fontconfig
   `open()`s each font directory before `getdents`-ing it; `open` and `read`
   are *separate* permissions of the `dir` class, so a `read`-only grant
   passes the permission check for the enumeration while the `open(2)` itself
   is still denied — the directory is never enumerated and the app silently
   renders without the user's fonts. In both, the audit line is an ordinary
   denial against an unremarkable object (a `tmpfs_t` lnk_file / a
   `user_fonts_t` dir) — the `tclass`/`ttype` in the record is the *carrier*,
   not the capability you were chasing. The discriminating test is always the
   consumer actually doing the op (the pty opens, the fonts enumerate), not
   the absence of denials. — *the enforcing-mode pty+font debug;
   `selinux/apse.cil`, `src/sandbox/mounts.rs`.*

36. **SCM_RIGHTS receive is a *separate* MAC check that runs against the
   *receiving* process — twice, against two different labels — and a denial
   drops the fd silently (only `MSG_CTRUNC` flags it), so a relay needs
   receive-side grants on *both* ends and must check the truncation flag at
   the point of loss.** The kernel's `security_file_receive` →
   `__file_has_perm` checks the **receiver** (not the sender) when a fd is
   delivered over SCM_RIGHTS: first `fd:use` against the file object's SID
   (for a `memfd_create`'d file that is the **creator's** SID, *not* any
   filesystem label), then the permissions implied by the fd's `f_mode`
   against the **inode's label** (for an anonymous fresh-tmpfs inode, the
   mount's default `tmpfs_t`, since `memfd_class=0`). Both must pass; a
   failure drops the fd from the received cmsg while the message **bytes**
   arrive intact — silent data loss, `MSG_CTRUNC` the only signal. (a) *The
   grant set must cover every process the relay touches, against the label the
   fd carries:* the relay receiving the app's wl_shm pixel pool needs
   `apse_app_t fd:use` **and** `tmpfs_t file (read write)`; the **compositor**
   receiving that same pool *forwarded* is checked too — the forwarder is also
   a receiver — so `unconfined_t apse_app_t fd:use` is mandatory (the base
   policy already covers its file read/write, which is why only the app type
   was new); the reverse (the compositor's `/dev/shm` XKB keymap — a
   `user_tmp_t` file of an unconfined creator — down to the relay, and the
   relay's copy on to the app) needs `fd:use` on `user_tmp_t` for *both*. (b)
   *The code must fail at the point of loss:* unchecked, the relay fails one
   parse later with a misleading `MissingFd` ("message references a fd that
   has not arrived") — the loss point and the failure point are far apart;
   `ProxySocket::recv` now checks `ReturnFlags::CTRUNC` after every `recvmsg`
   and errors with the actual cause. — *the enforcing-mode relay fd debug;
   `selinux/apse.cil`, `src/proxy/mod.rs`, kernel `security/selinux/hooks.c`.*

37. **A reaper that must live must never die on an interrupt — and supervision
   that lives only inside a process orphans everything when that process
   dies.** One incident (run #1: S died silently mid-run, A died shortly
   after, and the app's pidns — B is its PID 1, #13: immune to default-action
   signals from outside — ran on forever; the only trace was the sub-cgroup
   `rmdir` failing `ENOTEMPTY`) exposed two holes, both closed (v2.15). (a)
   `EINTR` was fatal in both reapers' blocking `waitpid`s (S's via `?`, A's
   via a 126 exit): both reapers block *exactly* the three signals they
   forward (the signalfd is their sole consumer), so every other signal is at
   default disposition and reaches them *delivered* — and a delivered signal
   interrupts a blocking `wait4`. The principle is universal: retry `EINTR` in
   a wait that has to live (a dead A reaps nothing; a dead S takes the 2 s
   KILL escalation — the only thing keeping B finite). (b) There was no
   backstop for *any* S exit with the app alive (an error `?`, a panic, a dead
   A reaped by S): the `AppKillGuard` is armed the moment the handoff
   completes and dropped at the end of the run; its `Drop` reads the instance
   sub-cgroup's `cgroup.procs` — recursive on cgroup2: A moved in before the
   unshare (#20) and B entered with it, so the list is A + B + every
   descendant — and SIGKILLs whatever is still there. It does *not* rely on
   the kernel's zap of a dying pidns init (#14: on 7.2.11 strays reparent and
   survive); on the normal path it is an empty no-op, and it fires — loudly —
   only when it finds a live process, i.e. exactly the incident.
   Field-verified by SIGKILL-ing A (old code orphans B+child; new code leaves
   no process). **Remaining boundary:** a default-terminate signal *to S
   itself* kills the guard with it (`Drop` runs only on unwinding exits, not
   on a fatal-signal death) — the actual run-#1 shape, closed by the
   kernel-level `PR_SET_PDEATHSIG` cascade (#42; full decision record: PLAN.md
   #41). — *the run-#1 orphan; `src/sandbox/mod.rs` (`waitpid_retry`,
   `AppKillGuard`), decisions #13/#14/#41.*

38. **Test tooling can outlive the session that spawned it — and leave *input*
   state behind.** Two orphans of the previous session's violent teardown,
   both invisible to normal triage. (a) **The ydotool wedge:** the input-e2e
   client was killed mid-sequence (a press without its release); the *daemon*
   (root, nohup'd) survived holding the key pressed, and a pressed key on a
   wlroots keyboard is auto-repeated by the compositor (sway: 600 ms delay, 25
   Hz) — so the user's real terminal behaved as if [enter] were broken
   (phantom Enters flooding the shell; typed commands sent early, the rest
   mis-parsed). The stuck state lives in the *virtual* device's per-keyboard
   state, so the fix is to destroy the device — kill/restart the daemon — not
   to poke the physical one; a release-only injection (`28:0`) clears it too.
   A daemon that can inject state into a shared system (input, clipboard,
   compositor) must be torn down with the test that drives it. (b) **The EOF
   spin:** a `python3 -` test helper (program from a pipe, IPC over a
   socketpair) whose coordinator died kept its `while not data: data =
   sock.recv()` loop — which then got EOF (0 bytes) on every call and
   "retried": 176k `recvfrom`/2 s, one core at 100% for 3.5 h. `recv() == 0`
   is the *closed* state, not "empty, try again"; any wait-loop that treats it
   as retryable never terminates. — *the post-restart incident (2026-10-30);
   ydotoold, `swaymsg -t get_inputs`.*

39. **Never run a probe that unshares a PID namespace and signals by numeric
   PID from inside a live desktop session — and never one without `kill()`
   auditing.** The pdeathsig probe (2026-10-31) was a C program run via the
   agent's `bash -c` inside the `foot` scope's cgroup that
   `fork`/`unshare(CLONE_NEWPID)`/`fork`'d an S→A→B shape and signalled by
   numeric PID; the same second the session's own `systemd` (the main process
   of `user@1000.service`) was SIGKILL'd, and systemd tore down the **entire**
   session (sway, every terminal, the agent) until the user rebooted. Three
   lessons. (a) **The obvious failure model is wrong, and that is exactly what
   made it feel low-risk.** `unshare(CLONE_NEWPID)` changes only
   `pid_for_children`, not the caller's own namespace (pid_namespaces(7)); so
   A's `kill(1, …)` operates in the *caller's* — the **host** — namespace,
   i.e. the system **init**, which is un-killable from userspace. The
   `kill(1)`s were **no-ops**; the death did *not* come from "I signalled PID
   1." (b) **The real hazard is that a freshly created pidns inside a session
   cgroup interacts with systemd's session machinery in a way you cannot
   safely reason about, and when it misfires it takes the session's *manager*
   with it** — `user@…` is the process systemd watches as the session main
   process; killing it cascades logind/sddm into a full teardown. The exact
   signal path was not recoverable: `auditd` had **no** `kill()`/`tgkill` rule
   active, so the journal shows only the cascade. (c) **Isolate and audit
   before you probe.** Run pidns/signal experiments in a context you can
   afford to lose (a dedicated VM, or a throwaway seat — a re-runnable
   desktop, not *the* desktop), and arm a `kill()`/`tgkill()` audit rule
   *beforehand* (`auditctl -a always,exit -F arch=b64 -S kill,tgkill -k
   pdeath`); read it back with `ausearch -k pdeath`. In-repo, the pdeathsig
   cascade is verified through **apse's own** supervised S→A→B pipeline (`run`
   — private rootfs, its own cgroup, no raw PID signalling); the unsafe thing
   is a hand-rolled raw probe in the live desktop. — *the 2026-10-31
   desktop-kill; pid_namespaces(7); the pdeathsig cascade (decision #42).*

40. **On 7.2, `PR_SET_PDEATHSIG` is neither inherited nor stable across exec —
   `fork` *resets* it to 0, and `execve` clears it *unconditionally* on any
   exec that changes the process's SELinux SID.** Verified against `v7.2.11`
   (`~/src/linux`), which also corrects an earlier wrong assumption in this
   codebase: the clear does **not** go through `bprm->secureexec`.
   `selinux_bprm_committing_creds` (`security/selinux/hooks.c:2545`, commit
   `4ac212ad4e8f`) sets `current->pdeath_signal = 0` whenever the exec changes
   the SID (`new_crsec->sid != new_crsec->osid`) — a confined run does
   (`apse_t` → `apse_app_t`/`xserver_t`) — and no permission can prevent it:
   this policy *grants* `noatsecure` on the `apse_t` → `apse_app_t`
   transition, so the `secureexec` path (`fs/exec.c`) does not even fire on
   the app's exec (it does on the `xserver_t` transition, where `noatsecure`
   is not granted, but the unconditional clear already covers it; the separate
   `commit_creds` clear on an actual uid/gid/caps change does not fire at all
   — same uid, no capability gain). The legacy paths remain, but on this
   policy the SID-transition clear is the mechanism that fires on every
   confined exec. Only a *same-domain* exec (the unconfined run) changes no
   SID and sets none of the clearing conditions, so the pre-exec belt
   survives. Consequences, all now encoded in `src/pdeathsig.rs`: (a) every
   link of a cascade must set its own value *after its own fork* — the value
   is not inherited (`kernel/fork.c`: `p->pdeath_signal = 0` unconditionally);
   (b) a process that execs into a different SELinux domain needs the
   post-exec `LD_PRELOAD` shim to re-arm the signal (decision #42's B←A link,
   decision #37's satellite) — belt (pre-exec set) and bridle (shim) are both
   load-bearing, not belt-and-bridle; (c) a signal the process will have
   *blocked* at delivery time never fires (it stays pending), so a pdeathsig
   must be one the receiver handles, not one it blocks (A keeps TERM/INT/HUP
   blocked, hence `SIGUSR1` for A's link). API drift: `PR_GET_PDEATHSIG`
   writes the value to the pointer in `arg2` and returns 0/`-EFAULT`
   (`kernel/sys.c`) — the ≤ 6.x convention of returning the value is gone, so
   a "read it back" test must check the output parameter, not the return. —
   *the decision-#42 implementation; `src/pdeathsig.rs`, `src/sandbox/mod.rs`,
   `src/xwayland.rs`.*

41. **A confined consumer can `mmap(PROT_EXEC)` a file only against labels its
   policy explicitly grants `file:execute` on — and on 7.2 a `filecon`
   statement is dead weight for created files, so the shim `.so` gets a
   dedicated type that `ensure_shim` applies with `setxattr`.** On 7.2.11 a
   `PROT_EXEC` file mapping is mediated as `FILE__EXECUTE`
   (`file_map_prot_to_av`, `security/selinux/hooks.c:4042`) — not just
   `FILE__MAP` — and no base-policy type grants `file:execute` to
   `apse_app_t`/`xserver_t` on a file in the instance runtime dir
   (`user_tmp_t`), so the shim `.so` has a dedicated type `apse_shim_t` (in
   the module's `mcs_constrained_type` set, granted `file (execute getattr map
   open read)` + `fd:use` to the two consumer types and nothing else). Two 7.2
   traps on the labeling path. (a) `filecon` does not label created inodes and
   its contexts are not pre-registered in the sidtab — `OCON_FILE` is gone
   from the kernel (the mechanism is dead code on this kernel) — so
   `ensure_shim` applies the label with `setxattr("security.selinux")` after
   compilation, and on the reuse path for a file left by an older build; the
   sidtab expands on demand (`sidtab_context_to_sid`), so no pre-registration
   is needed. (b) The `selinux_inode_setxattr` relabel check sequence ends in
   `FILESYSTEM__ASSOCIATE` whose **subject is the *new* label's SID** (not the
   relabelling process) and whose target is the **mount's** SID: the
   `/run/user/<uid>` tmpfs carries `tmpfs_t` (the sbsec default for a plain
   tmpfs — not `unlabeled_t`, which is the seclabel-only case), so the module
   must grant `apse_shim_t → tmpfs_t filesystem:associate`. A failed relabel
   degrades like a failed build (a warning); the user-visible symptom of a
   confined consumer hitting a mislabeled `.so` is `ld.so`'s "cannot be
   preloaded (failed to map segment from shared object)" — the belt then stays
   unset and a SIGKILL'd supervisor leaves its child behind (LESSONS #40). —
   *the decision-#42 shim; `selinux/apse.cil`, `src/pdeathsig.rs` (the
   `ensure_shim` relabel), `security/selinux/hooks.c`.*

42. **A vforked (or forked) child shares the parent's cred — so a pending
   one-shot exec context (`/proc/self/attr/exec`) is consumed by the *child's*
   `exec`, not the parent's, and the parent's cred keeps it until explicitly
   cleared.** `ensure_shim` compiles the shim with `cc` vforked by the std
   `Command`; in confined mode that child, sharing S's `apse_t` cred, would be
   carried by the module's `typetransition apse_t bin_t:process apse_app_t`
   into the *app* domain on its `exec` — losing the `tmp_t` dir/file grants
   for its temp files (a hard "Cannot create temporary file in ./" failure
   when the CWD is `/`, denials otherwise). The fix: before spawning `cc`,
   `pin_self_exec_context` writes the process's *current* context into
   `attr/exec`; the vforked child's `exec` copies the cred and consumes the
   pending SID (`bprm_set_creds`'s explicit-context branch — `new_crsec->sid =
   old_crsec->exec_sid`, `exec_sid` zeroed in the copy), so `cc` lands in
   exactly `apse_t:s0:cN`, and because old SID == new SID, `check_nnp_nosuid`
   takes its fast path (no `noatsecure` check at all). The parent's cred keeps
   the pending SID after the child's `exec` (the child got a *copy*), so
   `clear_exec_context` — an *empty* write to `attr/exec` zeroes it (7.2's
   setattr treats a zero-length value as "no context") — runs after the spawn
   attempt on every path; left stale it would be inherited by every later fork
   (the S→A→B pipeline) and a failed `attr/exec` write in one of them would
   exec into the supervisor's domain instead of the `typetransition` target. —
   *the decision-#42 shim compile; `src/pdeathsig.rs`
   (`pin_self_exec_context`/`clear_exec_context`),
   `security/selinux/hooks.c`.*

43. **Rust `String`/`Vec<u8>` are *not* NUL-terminated — passing one as a
   C-string argument to a raw libc FFI call makes the kernel read past the
   allocation into stale heap bytes, producing a mangled path that fails
   `ENOENT` while every log you print shows the path correctly.**
   `ensure_shim` passed `so.as_os_str().as_bytes().as_ptr()` to
   `libc::setxattr`/`libc::getxattr` for the SELinux relabel of the shim
   `.so`; the kernel reads the path as a NUL-terminated C string
   (`getname_kernel`), and a Rust byte buffer only guarantees validity through
   `len` — the allocator block underneath it carried stale bytes past that
   (the walk here wandered into a tail like `…10.soice/wlsctP`), so the
   relabel call failed `ENOENT` on a *mangled* path while the Rust `{:?}` logs
   all showed the clean one. The relabel degrades to a warning, so nothing
   failed loudly: a confined consumer simply could not map the mislabeled
   `.so` (`file:execute` is granted only on `apse_shim_t`, #41) and the
   pdeathsig belt stayed disarmed across the exec. The fix: pass a `CString`
   (which appends the NUL) — or a `Vec<u8>` with an explicit trailing zero,
   the `cstr()` helper pattern already used throughout `mounts.rs`. Note the
   asymmetry at this boundary: the *path* is a C string (you terminate it),
   the *value* is a counted length (the kernel NUL-terminates it itself,
   `kmemdup_nul`), so only the path needed the fix. Detector for the class: a
   path-based syscall failing `ENOENT`/`EACCES` on a path that logs correctly
   in the host language — a `strace` of the same call shows the kernel's
   actual (mangled) view. — *the decision-#42 shim relabel; `src/pdeathsig.rs`
   (`current_label`/`relabel_if_needed`).*

44. **The decision-#42 B←A belt *fires* — and only strace can see it: a
   pdeathsig delivery is a kernel-internal signal send
   (`forget_original_parent` → `group_send_sig_info`), not a `kill`/`tgkill`
   syscall, so it is invisible to any audit exit filter. Field-verified, with
   one open question that does not break the safety argument.** A strace of
   the whole S→A→B pipeline (app = `sleep`) caught the delivery exactly: on
   the SIGKILL of A, B (inside its pidns) shows `--- SIGUSR1
   {si_signo=SIGUSR1, si_code=SI_USER, si_pid=0, si_uid=<sender's uid>} ---`
   right after the shim's post-exec `prctl(PR_SET_PDEATHSIG, SIGUSR1)`. The
   signature is the kernel's own: `__send_signal_locked` fills `si_code =
   SI_USER` and `si_pid = task_tgid_nr_ns(current, task_active_pid_ns(t))` for
   `SEND_SIG_NOINFO` — and the dying A lives in the *ancestor* PID namespace,
   invisible in B's pidns, so the sender's tgid resolves to **0**: `si_pid =
   0` here is the *marker* of a pdeathsig delivery, not a hole (a real
   in-namespace `kill` shows the sender's number). The cascade then completes
   as designed: S's `wait4` returns A's death, the `AppKillGuard` sweep
   SIGKILLs what is left, the run exits 137, and no process survives. Traps
   from the same field test. (a) **The audit dead end:** because the delivery
   is not a syscall, no amount of `auditctl` rule-crafting can capture it; the
   strace signal line, or the receiver's pending-signal state, is the only
   window. (b) **The belt fired, yet B *survived* the USR1 — an open
   question.** B execs, so USR1 should be at `SIG_DFL` (terminate): exec
   resets every handler except `SIG_IGN`, the shim installs no handler, and A
   installs its USR1 handler only *after* the clone that creates B (B cannot
   inherit it; USR1 is not in B's mask). Yet the trace shows
   `restart_syscall`, which only exists when the delivered action carried
   `SA_RESTART` — not death; the final SIGKILL on B was the guard's, not the
   belt's. A control with an explicit `SA_RESTART` handler survives under
   strace too, so the survival is real, not a trace artifact; the leading
   suspect is an `SA_RESTART` USR1 action set somewhere in the Rust binary's
   ELF/dynamic-linker startup. Net: *delivery* is verified, *termination of
   the run* is verified (by the guard); the belt's own terminate-disposition
   is the one piece not cleanly isolated, and it is not load-bearing while the
   guard exists. — *the decision-#42 B←A field test (2026-11-03);
   `src/pdeathsig.rs`, `src/sandbox/mod.rs` (`AppKillGuard`); kernel
   `kernel/exit.c` (`forget_original_parent`), `kernel/signal.c`
   (`send_signal_locked`).*

45. **`/proc/<pid>/` is labeled with the *target process's own context*, not
   by the `proc_t` genfs rules — so self-`/proc` access (the comm restore, the
   MCS `attr/exec` write, the `exe` re-exec) runs against the process's *own
   type*, and the 7.2 `comm_write` no longer strips the newline you feed it.**
   `security_task_to_inode` (in the pident inode-creation paths) sets each
   `/proc/<pid>/` inode's sid from the task's sid, and `pid_update_inode`
   re-labels the whole `/proc/<pid>/` subtree on every credential change
   (setuid/setgid/caps/SELinux) — so a process that execs with
   `setexecfilecon` re-labels its *own* `/proc/self/` tree into the new domain
   (the MCS narrowing's `attr/exec` write and `/proc/self/exe` re-exec both
   run against self-typed files, which is why they needed no special grant —
   the existing `apse_t → apse_t` file allow covers them). The observed shape
   on 7.2.11: `/proc/1/` → `init_t`, `/proc/self/` → the reader's own context
   *including its MCS range*, while specific paths like `/proc/cpuinfo` still
   match their genfs rules (`proc_t`); the pid component matches no rule, so
   the subtree never falls back to `proc_t`. Two traps from fixing the "comm
   becomes `exe` after a `/proc/self/exe` self re-exec" break. (a) **The wrong
   grant:** the obvious fix is to grant `proc_t file:write` — but that file is
   the process's own type, so the grant never applies (and if a self-type
   grant were missing, the denial would read as a *self*-type hole, easy to
   miss). (b) **The newline:** 7.2's `comm_write` copies into a zero-padded
   buffer and passes it to `set_task_comm` as-is — the old `memchr('\n')`
   stripping is gone — so writing `"name\n"` leaves the newline *inside* the
   15-char comm (the file then reads back `"name\n\n"`); the write must be the
   bare name. The same 7.2 `comm_write` only accepts the write from the owning
   thread group (`same_thread_group`, else `EINVAL`) — cross-process comm
   renames, the older tooling trick, are dead; only self-writes work. — *the
   comm-restore fix; `src/main.rs`, `selinux/apse.cil`; kernel
   `fs/proc/base.c` (`comm_write`, `pid_update_inode`),
   `security/selinux/hooks.c` (`selinux_task_to_inode`).*

46. **A `typetransition` makes the exec *possible*; the exec-time cred hooks
   then check `noatsecure`/`rlimitinh`/`siginh` against the *new* SID, and
   their denial is a *silent degradation*, not a failure — while the real
   blockers of a satellite are its *inherited* fds (checked against the
   creator's type, `accept` included) and the teardown signals.** The
   `xwayland` satellite's exec into `xserver_t` was never blocked by the
   transition itself (`transition`/`dyntransition` + the `typetransition`
   entry were enough — Xwayland ran). On 7.2.15 three separate exec hooks each
   check the new SID — `selinux_bprm_secureexec` (denied → `bprm->secureexec =
   1`), `selinux_bprm_committing_creds` (denied → all soft rlimits reset),
   `selinux_bprm_committed_creds` (denied → itimers cleared) — and *none of
   them aborts the exec*: you only find out from the audit log, and the child
   runs with quietly-downgraded state. (The `apse_app_t` leg never showed the
   triple because this policy grants `noatsecure` on that transition; only the
   asymmetric `xserver_t` leg needed the extra permissions.) The failures that
   actually kept the satellite from working were all in the fd/signal layer.
   (a) The displayfd socketpair, the listening X socket, and the /dev/null dup
   carry the *creator's* SID (`apse_t`), so everything Xwayland does with them
   — `fd:use`, `getopt`/`shutdown`, and the socket's `read`/`write`/`accept` —
   is checked against `apse_t`, not `xserver_t` (the creator-SID rule of #36,
   in the *inherited-fd* shape; the exec's `flush_unauthorized_files` walks
   these same fds against the new cred, so the grant set has to be right
   *before* the exec). The load-bearing one is `accept`: without it every X
   client connection piles up in the kernel backlog, the server spins on
   `accept() failed`, and the display looks *up* to a connect probe while
   serving nothing — a denial that reads like a hang. (b) The satellite's
   TERM→2s→KILL teardown of the child needs `process (signal sigkill)` on the
   transition rule — the exec-time checks grant the *birth*; the teardown
   needs the *death*. Lifecycle surprise that is **not** an apse gap: Xwayland
   *creates* its `-auth` file on startup (a fresh magic cookie) and **unlinks
   it again on a clean shutdown** — the missing-file error is non-fatal (the
   server continues with no auth, and unauthenticated clients connect). — *the
   confined-mode verification of the `xwayland` satellite (2026-11-04, kernel
   7.2.15); `selinux/apse.cil`, `src/xwayland.rs`; kernel
   `security/selinux/hooks.c`.*

47. **The `wl_data_source` wire does not say whether its `send` (serve) is
   clipboard or drag — a source object is shared by both — and the v4 protocol
   has no `finished` event: a drag ends only on `cancelled`, `dnd_finished`,
   or the client's `destroy`, and `dnd_drop_performed` does *not* end it** (a
   drop with the `move` action transfers its data *at* the drop, so the serves
   that carry it arrive between `dnd_drop_performed` and the end event —
   clearing the drag on the drop event would mislabel them `clipboard`). The
   6.5.5 refinement therefore tracks the active drag in the relay: the last
   `start_drag`'s source (client-side only, i.e. in the gate's `own_sources`
   set; a new `start_drag` replaces the previous), cleared on
   `cancelled`/`dnd_finished`/`destroy`. The serve records on that source get
   `selection=drag`; every other stable source's stays `clipboard`, and the
   adjacent `read` on a stable-protocol offer stays `clipboard` too — a read
   is protocol-agnostic (the offer never says which drag or selection it
   belongs to), which is exactly the contrast the refinement exists to make
   (`drag_serve_is_audited_as_drag` asserts the three-way set=drag /
   read=clipboard / serve=drag). — *the 6.5.5 `serve`-label drag refinement;
   `src/proxy/clipboard.rs` (`active_drag_source`), `src/proxy/mod.rs` (the
   serve branch), `tests/proxy_integration.rs`.*

48. **In ripgrep 15, `--no-ignore` does *not* search hidden directories — the
   hidden-file axis is a separate flag (`-./--hidden`; `-u` is now
   `--unrestricted`, not the old `--unhidden`) — so a "zero matches" sweep
   done with `--no-ignore` silently misses everything under `.github/`,
   `.idea/`, and friends.** The wlsctx→apse rename (2026-11-06) was verified
   with `rg … --no-ignore -g '!target'` and reported clean;
   `.github/workflows/ci.yml` (a header comment) and `.idea/` (a *tracked*
   `wlsctx.iml` module descriptor, plus the run-config XMLs) still carried the
   old name, and were found only because `git grep` disagreed with the rg
   result. Two traps compounded. (a) **The flag semantics:** ripgrep skips
   dot-named files/directories by default, and `--no-ignore` only disables
   *ignore files* (`.gitignore`/`.rgignore`/excludes/global) — the hidden-file
   skipping is its own axis, `--hidden` (the `--no-ignore-dot` help text says
   so explicitly), and `-u/--unrestricted` is the cumulative alias (×1 =
   `--no-ignore`, ×2 = +`--hidden`, ×3 = +binary). A pre-15 habit of
   `--no-ignore` for "search everything" no longer searches everything. (b)
   **The negation-only glob masked it:** with `-g '!target'` as the only glob,
   the sweep's output was exactly the non-hidden files; a file set that
   *should* have been there was simply absent, and an empty region reads as
   "nothing to do" rather than "not searched" — there is no warning for an
   empty region, so the check passed on faith. The reliable "is it in the
   repo" check is `git grep` (it searches the index — every tracked file,
   hidden or not, regardless of ignore rules); `rg` stays the right tool for
   working trees where build artifacts must be searched too (for which use
   `--hidden -g '!target'`, or `-uu -g '!target'`). — *the wlsctx→apse rename
   (2026-11-06); ripgrep 15.2.0 `--help` (`-./--hidden`,
   `-u/--unrestricted`).*

49. **Baked lettering (one `<path>` per glyph, no `<text>`) is a *snapshot of
   a font*, not text — reword or rename and every glyph must be rebaked; and
   fontTools' `getBestCmap()` is keyed by *integer codepoint*, so a
   string-keyed lookup fails silently and any metric-matching built on it
   excludes every face it ever looks at.** The `wlsctx`→`apse` rename
   (feb3f76) updated the header SVGs' `aria-label`/`<title>` but left the
   wordmark's six baked glyphs spelling `wlsctx` (two teal `wl` + four amber
   `sctx`): a rename sweep that greps the string finds nothing, because the
   name exists only as path data. The rebake used Open Sans Bold (wordmark) /
   Regular (tagline): the original font is not installed and unidentifiable by
   name, but of the installed faces the Open Sans/Droid Sans family matches
   the original's metrics best — cap `W/xh = 1.308` exact, `l/xh 1.392`
   (observed 1.415), `p/xh 0.440` (0.409), bold stem width — and the one glyph
   it diverges on (lowercase `w`, ~20% wider in the original) no longer
   appears in either string. The string-keyed cmap trap cost a false
   conclusion first: "zero matches across 377 fonts" was produced by `c in
   cmap` with `c` a `str` against integer keys, so every face was silently
   dropped before a single metric was computed; the correct form is
   `cmap[ord(c)]`. — *the header rebake (2026-11-06);
   `assets/apse-header{,-tagline}.svg`, `AGENTS.md` (`assets/`).*

50. **SVG has no quadratic Bézier syntax, and fontTools' `Qu2CuPen` keeps
   quadratics by default — a baker that records only `curveTo` drops every
   segment it did not convert, and the broken contours render as "the fill is
   outside the letter shape."** `Qu2CuPen`'s default `all_cubic=False`
   converts only the quadratic runs it deems necessary and passes the rest
   through as `qCurveTo`; a recording pen handling
   `moveTo`/`lineTo`/`curveTo`/`closePath` only silently drops them, so every
   glyph lost most of its curve points — contours closing across the letters
   and the nonzero fill painting regions that are not the letters (the visible
   symptom: some letters only partly, fill outside the letter shape). The
   tempting diagnosis is a winding/fill-rule bug, but a uniform y-flip (font
   y-up → SVG y-down) reverses *all* contours together and the nonzero rule
   only cares about the *relative* winding of a counter and its container —
   which the flip preserves, so a uniform flip is never the culprit. The
   winding fact that does matter (and the only safe check): a *nested* counter
   must wind opposite its container, while disjoint contours (an `i`'s dot)
   may wind either way, so flag same-sign pairs only when one bbox encloses
   the other. Fix and verification: `Qu2CuPen(rec, max_err, all_cubic=True)`
   plus an assert that no other pen op reaches the recorder
   (`scripts/bake_header.py`); verify without eyeballing — sample each
   contour's signed area for the nesting check, and compare the RSVG render of
   the file's own paths pixel-for-pixel against FreeType rendering the real
   font at the baker's exact geometry (a correct bake lands at 0.4–0.6% diff /
   75–92% ink IoU; the broken one at 0.8–5.3% / 33–59% — for the small glyphs
   diff barely moves, IoU is the gate that separates; count *dark* pixels — a
   threshold lambda mapping dark→0 silently renames the background "ink" and
   inflates every number ~20×). — *the header rebake fix (2026-11-06);
   `scripts/bake_header.py`, `scripts/verify_header.py`.*

51. **The exit status of a failed *redirection* is shell-specific (bash: 1,
   dash: 2, POSIX only guarantees "non-zero") — a test that captures `$?`
   after a redirect and asserts the exact code silently assumes the
   developer's `/bin/sh`.** The supervisor's write-denial probe
   (`openat_write_denied_outside_granted_subtrees`) ran `echo x > <denied>
   2>/dev/null; a=$?` and asserted `a=1` — written on Fedora (`/bin/sh` =
   bash). The first time it ran on Ubuntu (the GH runner, `/bin/sh` = dash)
   the *same* denial yielded `a=2` and the test failed although the sandbox
   behaved exactly as designed (the supervisor log showed `deny write … (not a
   granted subtree): EACCES`, the file was not created, and the granted write
   succeeded and read back). POSIX mandates only "the exit status of the shell
   or sub-shell shall be greater than zero" for a redirection error; bash
   chose 1, dash 2. The property under test is the *denied/allowed*
   distinction (and the filesystem state), not a code, so the fix normalises
   *in the script* (`cmd && a=0 || a=1`): the assertions keep their meaning on
   both shells, and the denial's authoritative proof (the file is absent on
   the host) is asserted separately. Detector for the class: an exact-code
   assertion that derives from a *redirection or built-in failure* (rather
   than the command's own exit path) breaks when an image's `/bin/sh` changes
   family — and a test that has only ever run on one family (bash on the dev
   box) reveals it on the first cross-distro run. — *the ubuntu-26.04 CI
   second pass (2026-11-06); `src/sandbox/supervise.rs`.*

52. **A sandboxed app inherits the *launcher's* CWD, not its own — and in a
   private-home sandbox that path may not exist, so an app that `chdir(cwd)`s
   before its exec (foot's `slave_spawn`) dies on a vanished directory and
   misreports it as "failed to execute".** The CWD is process state carried
   across `fork`/`exec` just like an env var: B (the process that `exec`s the
   app) inherits S's CWD, the host directory `apse run` was launched from. In
   private-home mode (decision #43) that directory sits under the real home,
   and the rootfs build replaces the real home with the per-app private tree —
   so the inherited CWD points at a path that no longer resolves (`ENOENT`).
   The failure is invisible to the supervisor: a bad `chdir` is not a trapped
   syscall (only `openat`/AF_UNIX are notified), so there is no `deny` line
   and the app simply never appears. foot is the canary: its `slave_spawn`
   `fork`s and, in the child, `chdir(cwd)`s *before* `execve`, and a failed
   chdir `_exit(errno)s` before the exec, which the parent mislabels
   `slave.c:554: …: failed to execute`. The fix makes the CWD part of the
   sandbox contract: B `chdir`s to the app's home (the `$HOME` string, which
   the rootfs binds resolve to the private tree) *before* the exec, and before
   the seccomp-notify filter and Landlock floor are installed so neither can
   mediate the chdir (the mount namespace is already up, inherited from A);
   host mode is left as-is (its inherited CWD is a real, existing path).
   Detector for the class: an app that "fails to execute" with zero supervisor
   `deny` lines and no `execve` in `strace` is probably dying in a
   `chdir`-style *pre-exec* step on state the sandbox silently changed — check
   the CWD, not the binary. — *decision #43 private-home, the foot
   `slave_spawn` failure (2026-11-11, kernel 7.2.15); `src/sandbox/mod.rs`
   (the B-side chdir), `src/sandbox/mounts.rs` (`chdir`); foot 1.28
   `slave.c:397–401,554`.*

53. **A *module* type joins no base-policy attributes by default, so the
   sweeping grants that make stock `*_exec_t` binaries manageable
   (unconfined's `file_type` file lifecycle, including `unlink`) never reach
   it — and the fix is to opt the type into the *standard attribute set*, not
   to enumerate permissions by hand.** `unconfined_t` (via the
   `files_unconfined_type` attribute) has a catch-all `allow … file_type:file
   { … unlink … }`; base types like `ssh_exec_t` are `file_type` members, so
   `sudo rm` of them "just works". A module type (`apse_exec_t`) joins no
   attribute unless the module says so — so the *delete* leg of the update
   cycle (`unlink`) had been omitted (the install/update set
   `write`/`setattr`/`relabel*`/`ioctl` was there), and `sudo rm
   /usr/local/bin/apse` failed with a bare `{ unlink }` denial. The full fix:
   make the type what it actually is — a standard application executable — the
   same attribute set the base policy gives `ssh_exec_t`/`sudo_exec_t`
   (`seinfo -t <type> -x`: `file_type`, `exec_type`, `entry_type`,
   `application_exec_type`, `non_auth_file_type`, `non_security_file_type`).
   Auditing the set *before* joining (`sesearch --allow -t <attr> -dt -p
   write`) shows the feared write hole does not exist: the only user-space
   writer of `file_type` is `unconfined` itself (the relabel types are
   relabel-only), the writers that do exist on
   `non_auth_file_type`/`non_security_file_type` apply *identically* to the
   ssh binaries (parity, not a delta), and no write grant on any of the six
   reaches `apse_t`/`apse_app_t` — the real boundary (the sandboxed app cannot
   modify the manager) is untouched. `entrypoint` is the one permission the
   attributes do not cover — granted explicitly by the defining module (the
   base pattern, see the per-type grants on `sudo_exec_t`) and required for
   the `unconfined_t → apse_t` transition. Detector for the class: a `sudo
   rm`/`chcon` denied on a type you defined in a module while the same op
   succeeds on a stock `*_exec_t` — the difference is attribute membership;
   audit the attribute's actual grants and join the set, *not* assume
   membership "re-opens the hole". Related trap from testing:
   `filesystem:associate` (checked on *relabel*, with the new label as
   subject) is per-filesystem-*type* — the module grants it for the btrfs
   root's `fs_t` but not `tmpfs_t`, so a scratch file can be `chcon`'d to
   `apse_exec_t` on `/` but not on `/tmp`. — *the `sudo rm
   /usr/local/bin/apse` failure and the attribute-parity rework
   (2026-11-11/12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

54. **On 7.2 the inotify watch is a MAC check (`inotify_add_watch` is mediated
   against the `watch` permission — the permission existed for years but this
   kernel is the first to enforce it) — and an interactive shell's full state
   pattern (flock, inotify live-reload, atomic save via `setattr`/`rename`,
   `read` *and* `open` on every dir it enumerates, plus probe ioctls on files)
   is a predictable denial class, every fix of which is user-data-scoped or
   read-only — none opens the jail.** Fish in the private home (decision #43)
   inside the sandbox produced ~120 denials, all in these shapes: (a) `dir
   (lock watch)` on its *own* config dir — fish flocks the dir and
   inotify-watches it for live-reload; on 7.2.15 the watch is checked, so this
   class is 7.2-specific (older kernels let the watch through — the missing
   check was the accident, not a deliberate grant); (b) `file (setattr
   rename)` on its *own* state files — the save is create-temp → write →
   `setattr` → `rename` over the final name, outside the existing
   `create/write/unlink` grant set; (c) `dir (read)` — and, once granted, `dir
   (open)` — on every enumerated dir (fish's completion enumeration of
   /usr/bin + /bin, man's section subdirs, `ls /`): `open(2)` on a directory
   is a *separate* check from `getdents` (the dir-open trap of #35), so
   enumeration targets need both; (d) probe ioctls against files — the loader
   probes the just-opened exe/`.so` with a tty ioctl (TCGETS2) at exec, and
   man queries the page file's extents (FS_IOC_FIEMAP); on 7.2 both are
   checked against the file's type (`file:ioctl`), and a denial degrades
   silently but is still logged; (e) `dir (getattr)` on the root dir's
   remaining entry types (git's statx on /usr/share/locale, `ls /`'s per-entry
   stats on /afs — `mnt_t` is the one unmasked root-level type outside the
   covered set). All fixes are additions to the existing per-type grant sets
   in `selinux/apse.cil` — user-data-scoped (the app's own home tree) or
   read-only system dirs, no cross-user or system write — verified zero-denial
   in enforcing with a pty-driven interactive fish (flock + inotify +
   save-on-exit, `ls /`, `man ls`, `git --version`). Detector for the inotify
   piece: a 7.2 `watch` denial on a directory the app *owns* (its own config
   dir) is not a jail escape — an app watching its own state is intended
   behaviour. — *the fish-in-foot denial round (2026-11-12, kernel 7.2.15,
   enforcing); `selinux/apse.cil`.*

55. **On audit 4.2.1 (Fedora 45), `ausearch -ts <time>` — and `--start` with a
   relative or bare-keyword spec (`10min`, `60min`, `today`) — silently
   matches *zero* records, so a "zero denials" verification built on it passes
   vacuously.** `--start recent` (the start of the current `audit.log` file)
   works, and `--start "YYYY/MM/DD HH:MM:SS"` works; the relative forms return
   an *empty result set without error* even while the daemon is clearly
   logging (the same records are present in `/var/log/audit/audit.log` by
   direct `grep`). The false negative passed twice in one session before being
   noticed — both times against a module that demonstrably had new denials.
   Detector: a "clean" audit window that contradicts observed behavior (the
   app visibly degrading, or a known denial shape from minutes earlier) —
   before trusting a negative, sanity-check the query against a record you
   *know* exists, or bypass the query entirely with a file-grep baseline
   (count `type=AVC … denied` lines in the log before and after the run and
   diff the tails): the file is immune to the tool's time-parsing quirks. —
   *the fish-in-foot denial round's verification (2026-11-12); audit 4.2.1
   (`ausearch --start`/`-ts`).*

56. **The module-store CIL dialect has no `filetrans` keyword — a *filename*
   transition is spelled as the five-field `typetransition` (`src tgt class
   "name" child`), the quoted name distinguishing it from the four-field
   process form.** `semodule -i` on a CIL containing `(filetrans …)` fails
   `Unknown keyword filetrans / Failed to build AST`; probing libsepol 3.11's
   CIL reader with a test module showed the reader has only `typetransition`,
   with the arity (4 = process, 5 = filename, name literal) selecting the
   meaning — the probe `(typetransition unconfined_t user_home_dir_t dir
   "probe" <type>)` installed cleanly and `sesearch` rendered the expected
   `type_transition …:dir <type> probe;`. This is the inverse of the
   checkmodule -C trap (the README's note on the *compiler* writing the wrong
   class in the 4-field form): here the dialect itself lacks the file keyword,
   so hand-written CIL must spell both the class (`dir`, not `file`) and the
   arity. — *introducing `apse_state_t` (2026-11-12, libsepol 3.11, kernel
   7.2.15); `selinux/apse.cil`.*

57. **On 7.2, `filecon` does not label *created* inodes — a new inode's label
   comes only from (a) the mountpoint default, (b) the process' `create_sid`,
   or (c) a filetrans; and the no-rule default of `security_compute_sid` is
   the *parent's* own type, so one named filetrans labels an entire subtree,
   any depth, on any fs.** `selinux_determine_inode_label`
   (`security/selinux/hooks.c`) consults exactly those three sources; a
   filecon matching the path is used by `restorecon`/`setfiles` and by
   setxattr relabel, never at creation. Making the per-app state tree a
   dedicated type therefore takes: a named filetrans on the *root* dir
   (`apse_t` creates `apse` under a `gconf_home_t` parent → `apse_state_t`),
   no per-child rules (children fall through to the parent's type), and the
   MLS range follows the parent's low level (`s0` target-low, dominated by
   every `s0:cN` — the tree stays reachable from every instance, same as the
   session dir). Pre-existing (pre-module) inodes are not relabelled by any of
   that, so S does a one-time setxattr walk of the whole tree
   (`prepare_app_state` → `relabel_state_tree`, the `apse_shim_t` mechanism:
   the 7.2 relabel path checks ownership, `relabelfrom`/`relabelto` against
   the *old* and *new* labels respectively, the `validatetrans` constraint,
   and `associate` with the *new* label's SID as subject; the getxattr
   pre-check for the current label carries no MAC check at all —
   `selinux_inode_getsecurity` only converts the inode's SID). Detector: a
   newly created dir keeps the parent's or fs-default label even though a
   filecon "should" match its path — before blaming the filecon, check that
   something actually *transitions* to the type at creation. — *`apse_state_t`
   (2026-11-12, kernel 7.2.15, `hooks.c` `selinux_determine_inode_label` +
   `ss/services.c` `security_compute_sid`); `selinux/apse.cil`,
   `src/sandbox/mounts.rs` (`relabel_state_tree`).*

58. **The unconfined home-dir access on the stock home types is
   *attribute-mediated* — a dedicated non-attribute type gets none of it, so
   the user's lifecycle must be mirrored by explicit grants; and the
   private-home rootfs makes `mounton` on that tree load-bearing for *both*
   the confined A and the unrelabeled test-suite pipeline.** Unconfined's "do
   anything in your home" comes from the `file_type` attribute grant plus the
   userdomain-family grants (LESSONS #53 for the general principle; this is
   its home-tree consequence): `apse_state_t` joins no attribute, so
   `unconfined_t` needed the full lifecycle mirrored by name (dir `add_name
   create getattr ioctl lock mounton open read remove_name rmdir search
   setattr unlink watch write`, file `… rename …`, lnk_file). Two specifics of
   this tree: (a) the test suite's apse is unrelabeled (`unconfined_t`) and
   runs the *same* pipeline, so its `prepare_app_state` chmods and A's
   private-home binds all hit the tree's type — the missing `mounton` there
   surfaced as 18 `rootfs construction failed: … Permission denied` test
   failures, not a single readable denial; (b) `mounton` matters for the binds
   *specifically because of the home substitution*: once the home bind has
   replaced `/home/user` with the tree's `home` subdir, every later XDG bind
   target (`.config`, `.cache`, …) resolves to a dir *of the tree* — source
   and target are both `apse_state_t`, and the `mounton` check runs against
   the target. Detector: an EACCES on `mount(2)` where both source and target
   dirs are your own dedicated type — think `mounton`, not `search`/`read`. —
   *`apse_state_t` (2026-11-12, kernel 7.2.15, enforcing);
   `selinux/apse.cil`.*

59. **`/proc/<pid>` carries the *target process's* context (its whole subtree
   does), so a tool that stats or ioctls its own process entry in /proc needs
   a *self-referential* grant — and `ps`'s full surface is
   `proc_t`/`sysfs_t`/`sysctl_kernel_t` dirs each needing `open` *and* `read`,
   plus that self `dir:ioctl` for the tty probe.** `ps` in a sandboxed foot
   (user-reported: it errored, the table never appeared) produced four shapes:
   (a) `proc_t:dir open` + `read` — the /proc enumeration (#54's open-vs-read
   class); (b) `sysfs_t:dir open` + `read` — the /sys CPU/NUMA walk for the
   processor count; (c) `sysctl_kernel_t:dir search` + `file read` — the type
   is `/proc/sys/kernel` (a type of its own, like vm/crypto; the naive guess
   is a non-existent `/proc/kernel`), which ps reads for `pid_max`; (d)
   `apse_app_t:dir ioctl` on its *own* `/proc/<pid>` dir — ps's TIOCGPTN tty
   probe (the #40 probe class), targeted at the process's self-label, so the
   grant is on the app's own type. (d) is MCS-safe by construction: a
   single-level `s0:cN` subject dominates only same-category objects, so the
   self grant cannot reach another instance's processes. Detector: a `denied {
   ioctl }` on a `/proc/<pid>` path with scontext == tcontext modulo level —
   the object is self-labeled; the fix is a self grant, not a `proc_t` grant.
   — *`ps ax` in the sandboxed foot (2026-11-12, kernel 7.2.15, enforcing);
   `selinux/apse.cil`.*

60. **`statfs(2)` is mediated against the *mounted filesystem's* type — the
   `filesystem` class, the `filesystem_type` attribute family — never against
   the path's label, so `df` (which statfses the root of every mount it sees)
   needs a grant on that family, and one attribute covers all of it.** `df
   /run` in the sandbox produced one denial per mount — `tmpfs_t`, `device_t`
   (devtmpfs), `fs_t` (the btrfs root), `proc_t`, `sysfs_t`, `cgroup_t`
   (cgroup2) — each `denied { getattr } … tclass=filesystem` with the
   *mount's* type as target. The check's target is the superblock's SID, so no
   grant on the directory's type can ever fix a `statfs` denial. `getattr` on
   this class is superblock metadata — fs type name, total/free size — and
   reads no file content, which is what makes the attribute grant safe: it
   lets the app *measure* every filesystem it can see, nothing more. The
   attribute is the complete target set — `seinfo -t tmpfs_t -x` / `seinfo -t
   device_t -x` both show `filesystem_type`, and the family is the
   `filesystem`-class members (`tmpfs_t`, `device_t`, `fs_t`, `proc_t`,
   `sysfs_t`, `cgroup_t`, …); a per-type grant would have to be re-added for
   every mount type the sandbox introduces. One adjacent shape: `df` also
   stats `/proc/sys/fs/binfmt_misc` to detect that mount — `/proc/sys/fs` is
   its own `sysctl_fs_t` type (like `sysctl_kernel_t`/`sysctl_vm_t`), needing
   `dir (getattr search)` plus `file (getattr open read)`. Detector: a `denied
   { getattr }` with `tclass=filesystem` — grant the *attribute*
   (`filesystem_type`), not the one type in the denial line. — *the `df /run`
   denials (2026-11-12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

61. **`lnk_file:getattr` (the lstat of the link itself) and `lnk_file:read`
   (the readlink) are *separate* checks — without the former, `ls -la` prints
   `l??????????`: getdents knows it is a link, but the denied lstat hides the
   target name.** `ls -la /dev` in the sandbox showed `l??????????` for
   `/dev/ptmx`; the denial was `denied { getattr } … tcontext=…:tmpfs_t:s0
   tclass=lnk_file`. Two traps compound. (a) *The label:* the sandbox's ptmx
   is a *relative* symlink into the fresh per-instance devpts (decision #39),
   so it lives in the fresh tmpfs and carries the fs default `tmpfs_t` — not
   `ptmx_t` (the v2.14 note that this symlink is `tmpfs_t` is the same fact
   from the relay's side; the earlier grant only covered `read`). (b) *The
   class split:* a listing lstats the link (the `getattr` that yields the
   target name and the size) before it readlinks it; the name column is
   populated from the lstat, so a `read`-only grant degrades the entry to
   `l??????????` instead of failing the command. The same split applies to the
   symlinks among per-purpose exec types (#62): the readlink is `getattr` +
   `read`, not `read` alone. Detector: an `l??????????` entry in a listing (or
   empty output from a readlink-based tool) alongside a `lnk_file` *getattr*
   denial — add the getattr, not another read. — *the `ls -la /dev` ptmx
   denial (2026-11-12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

62. **Fedora labels most of `/usr/bin/*` and `/usr/libexec/*` with per-purpose
   exec types, not `bin_t` — so a tool that stats every entry it enumerates
   (fish's completion) targets the `exec_type` attribute, the superset of
   every `*_exec_t`.** Once the `bin_t:dir open` grant (#54) let fish
   enumerate `/usr/bin`, the *next* class was `denied { getattr }` on **each
   enumerated entry** — `lvm_exec_t`, `iptables_exec_t`,
   `systemd_systemctl_exec_t`, `fsadm_exec_t` (dnf-utils), …: the directory
   grant lets you see the names, but the per-entry stat is a separate check
   against each entry's own type, and the `bin_t` grant only reaches the
   entries that actually are `bin_t`. The per-purpose types are dozens of
   individually-named types, each from its own module/filecon — the complete
   target is the **`exec_type` attribute** (the same attribute set the base
   policy uses for unconfined's exec access, which includes `bin_t` itself):
   `file:getattr` for the stat, and `lnk_file:(getattr read)` for the symlinks
   among them (#61's split). The grant is read-only by construction — no
   `execute`/`entrypoint` on the attribute — so the app cannot run any binary
   it is not meant to run; the existing transition set is untouched. Detector:
   per-entry `getattr` denials spread across a *set* of `*_exec_t` types while
   enumerating a directory — the target is an attribute, not the single type
   in any one denial line. — *fish completion in the sandbox (2026-11-12,
   kernel 7.2.15, enforcing); `selinux/apse.cil`.*

63. **A tool that maps its controlling tty back to a `/dev/pts/<N>` name
   *enumerates* the devpts root — in the sandbox, the fresh per-instance one —
   so the `devpts_t:dir` grant needs `open` + `read` (the opendir/getdents
   pair), not just `search`.** The pty-driven fish verification (run after the
   #62 completion fixes) produced exactly one remaining denial: `denied { read
   } for comm="fish" name="/" dev="devpts" … tclass=dir` — fish asks the
   kernel for its tty (the #40 probe class), then walks `/dev/pts/` looking
   for the entry whose inode matches. This is the #54/#59 open-vs-read class
   on a directory: `open(2)` on a dir is a separate check from `getdents`, and
   `search` (traversal) covers neither. The grant grew from `(getattr search)`
   to `(getattr open read search)` — the chr_file side
   (open/read/write/getattr/ioctl on the slaves) was already complete. Scope
   note: the enumeration is against the *fresh* per-instance devpts (only this
   instance's ttys, `s0` by the parent-low rule) — the host's devpts is never
   visible inside the sandbox, so the grant cannot be used to read another
   instance's tty names. — *the pty-driven fish verification (2026-11-12,
   kernel 7.2.15, enforcing); `selinux/apse.cil`.*

64. **The `cwd`/`exe`/`root` links of `/proc/<pid>` are labeled with the
   *target process's own* type (the whole pident tree, #45) — so a listing of
   `/proc/self` hits a *self*-labeled `lnk_file`, and the fix is a *self*
   grant with *both* `getattr` and `read` (#61's split applied to a self
   object).** `ls -laZ /proc/self/` in the sandbox printed `l??????????` for
   `cwd` and `exe`: the denial was `denied { getattr } …
   scontext=…:apse_app_t:s0:cN tcontext=…:apse_app_t:s0:cN tclass=lnk_file` —
   scontext and tcontext identical. #45 (the pident inodes take the target
   process's context) means the app's *own* links are not `proc_t` but its own
   domain, and #61 means the existing self grant `(lnk_file (read))` covered
   the readlink but not the lstat that supplies the target name in a listing.
   The grant grew to `(lnk_file (getattr read))`. The self grant is MCS-safe
   in effect: a single-level `s0:cN` subject dominates only same-category
   objects, so it cannot reach another instance's pident links (the same
   argument as #59's self `dir:ioctl`). The *top-level* self links
   (`/proc/self`, `/proc/thread-self`, `/proc/mounts`) are a different case:
   the genfs rule labels them `proc_t` (not self), so they needed only
   `getattr` added to the existing `proc_t:lnk_file` grant. Detector: a
   `lnk_file` getattr denial with scontext == tcontext (modulo level) — a self
   object; the fix is a self grant, not a `proc_t` grant. — *`ls -laZ
   /proc/self/` in the sandbox (2026-11-12, kernel 7.2.15, enforcing);
   `selinux/apse.cil`.*

65. **`/proc/net` is a *relative* symlink (`self/net`) — the link and the
   content behind it are different types, so following it needs grants on
   *both* layers.** fish (which readlinks `/proc/net` at startup) produced
   `denied { read } … tcontext=…:proc_net_t:s0 tclass=lnk_file`: the genfs
   rule labels the top-level `/proc/net` link `proc_net_t`, not `proc_t`.
   Following the link lands in the process's *own* `/proc/<pid>/net` dir
   (self-labeled `apse_app_t` by #45), whose *files* (`dev`, `arp`, `can`, …)
   are `proc_net_t` again by the genfs rule — so content access needs `file
   (getattr open read)` on `proc_net_t` in addition to `lnk_file (getattr
   read)` on the link, and `dir (getattr open read search)` for the
   `can`/`ip`/… subdirs (#54/#59's open-vs-read class). The content is
   read-only network state — in the sandbox, the private netns (loopback only)
   — so no write is granted. Trap: fixing the link makes `stat /proc/net`
   work, but `head /proc/net/dev` is still denied — the content is a separate
   check against a different object (a `proc_net_t` file, not the self-labeled
   dir it sits in). Detector: a `read` denial on the `/proc/net` *link*
   followed by an `open` denial on a `proc_net_t` *file* — you need both
   layers, not just the link. — *fish and `head /proc/net/dev` in the sandbox
   (2026-11-12, kernel 7.2.15, enforcing); `selinux/apse.cil`.*

66. **Top-level `/proc` entries are mostly *not* `proc_t` — each has its own
   dedicated genfs type, and `ls /proc` stats them all, so the grants are
   per-type `getattr` (and `getattr`-only is the safe bound).** `ls /proc` in
   the sandbox produced one `denied { getattr }` per non-`proc_t` entry:
   `sysctl_irq_t` (`/proc/irq`), `proc_psi_t` (`/proc/pressure`),
   `proc_kmsg_t` (`/proc/kmsg`), `mtrr_device_t` (`/proc/mtrr`),
   `proc_kcore_t` (`/proc/kcore`), `proc_mdstat_t` (`/proc/mdstat`),
   `system_map_t` (`/proc/kallsyms`), `sysctl_t` (`/proc/sysrq-trigger`) — the
   same shape as `sysctl_fs_t`/`sysctl_kernel_t`/`sysctl_vm_t` from #60/#59:
   the `/proc` root is a grab-bag of individually-typed entries (the
   `/proc/sys/<subtree>` dirs plus a handful of top-level files/dirs), the
   rest of the tree is `proc_t`. A listing only stats (no content read), so
   `getattr` alone is sufficient and is the right bound: deliberately no
   `open`/`read` on `proc_kcore_t` (kernel memory) or `proc_kmsg_t` (the
   kernel log). Detector: a listing-produced `getattr` denial spread over a
   *set* of individually-named `/proc` types — add per-type getattr; the
   target type in each denial line is authoritative (do not guess the entry is
   `proc_t`). — *`ls /proc` in the sandbox (2026-11-12, kernel 7.2.15,
   enforcing); `selinux/apse.cil`.*

67. **The module-store CIL reader (libsepol, the library `semodule` links)
   takes *one* class per `allow` rule — the multi-class form is rejected at
   install with a terse `Bad allow rule`, and the installed policy corpus
   never contains one, so nothing to model it on.** Collapsing the per-type
   `/proc` stat grants onto the `proc_type`/`sysctl_type` attributes, the
   natural form is one statement per attribute with one class group: `(allow
   apse_app_t proc_type (file (getattr)) (dir (getattr)) (lnk_file
   (getattr)))` — `semodule -i` fails `Bad allow rule at
   /var/lib/selinux/targeted/tmp/modules/400/apse/cil:N / Failed to build
   AST`; the one-class-per-`allow` form (one rule per attribute × class)
   installs cleanly. The constraint is in the reader's AST builder, not in CIL
   as a language: a scan of every loaded module (the 3.11 store keeps
   bzip2-compressed CIL under `…/active/modules/` — decompress before
   grepping; raw `cat`/`grep` is binary) found not a single multi-class
   `allow` — the classic checkpolicy pipeline emits one class per rule, so no
   installed module has ever exercised the multi-class path. The *attribute*
   as target is not the problem — the base policy is full of them
   (`stapserver_t → filesystem_type`, `container_userns_t → proc_type`,
   `domain → file_type`) — only the multiple-classes-per-statement form is
   unreachable. A second trap from the same session: an unprivileged `semodule
   -l` fails (`libsemanage … Could not read from module store … (Permission
   denied)`) and shows *nothing*, so a load check needs `sudo`. Detector: a
   `Bad allow rule` on a CIL line that looks well-formed — check whether the
   statement combines more than one `(class (perms))` group and split it. —
   *the attribute-based /proc stat redesign (2026-11-12, libsepol 3.11, kernel
   7.2.15, enforcing); `selinux/apse.cil`.*

68. **A module domain's self-grants stay an *explicit* mirror of the base
   policy's own `domain` set, not `domain`-attribute membership — the
   attribute is two-sided and the *subject*-side (`domain → X`) is the one
   that matters: the app→host escape surface, gated today by the same
   pidns/rootfs/seccomp that make `container_t` a safe `domain` member, but
   apse's primary controls are built by apse itself and the app runs as its
   real uid (no uid-mapping safety net), so pre-emptively importing the
   standing grant would disarm the independent second layer and drift with
   base updates; the *target*-side (`X → domain`: the host user
   signaling/killing the app) is the intended podman-model direction and is
   *not* a reason to reject.** The v2.25 pass (2026-11-12, enforcing) rejected
   `typeattribute apse_app_t domain`; the line-by-line audit is the comment
   block in `selinux/apse.cil` (tuning notes: `selinux/README.md`). Facts
   measured against the live avtab. (a) The *subject*-side adds **121 active
   `domain → X` rules across 74 host types** (126/76 counting rules gated by
   off-tunables) — the escape surface: reads across the base file families,
   `setrans_t` translate, `systemd_resolved_t` `connectto`, `kernel_t
   module_request`, `process {sigchld signull}` probes to the privileged
   types, socket-receive against `unconfined_domain_type` et al. (b)
   `container_t` is a safe member because a *normal* sandbox gates most of
   that reach with the primary controls: it is a privileged container
   *runtime* domain (260 attributes, incl. `can_load_policy`/`can_setenforce`
   — the svirt orchestrator of a private pidns with *mapped* uids), not a
   confined application; apse has no such net (the app runs as its *real* uid,
   decision #9, and every primary control is built by apse in one process
   tree) — that is why the module stays the *independent second layer* and the
   explicit mirror is what the tuning loop audits (a denial → a grant),
   whereas the imported set would drift silently with base updates. (c) The
   *target*-side (851 active `X → domain` rules, e.g. `unconfined_domain_type
   → domain: process {…signal sigkill…}`) is the *intended* host→app direction
   — verified live with zero AVCs (`TERM` is discarded by the pidns-init rule,
   `KILL` ends the run). (d) The base process neverallows (FSP 45.24's
   `domain.te` :59, :116-117) block nothing here: the installed policy
   enforces none of them (a violation is refused at `semodule -i`) and joining
   adds none. Authoring traps the *literal* mirror (raw CIL has no macros)
   surfaced: the `sem`/`shm` classes have **no `ioctl` permission** (a `Failed
   to resolve permission` at `semodule -i` is the detector), and on a
   `fips_mode`-on box the fifo self-grant must be the `manage_fifo_file_perms`
   superset. Two documented-but-not-tested reachability facts: the only
   missing `map` case for a file reader/writer is PROT_NONE — the body of
   `domain_can_mmap_files`, which is *off* on this box (`getsebool` is
   authoritative; the sesearch `[tunable]:True` annotation is the condition's
   *polarity*) — and `lnk_file:lock` is granted (the `domain.te` shape) but
   unreachable by any unprivileged process (the only fd to a symlink is
   `O_PATH`; every locking path rejects an `FMODE_PATH` fd with EBADF *before*
   the LSM; `ioctl` *is* testable — `security_file_ioctl` fires at syscall
   entry). Layering note: a zero-AVC EACCES in the sandbox is the *seccomp
   floor* (nono auto-rejects, #25), not SELinux. Detector: a *module* type
   whose denial audit keeps surfacing grants the *base policy's own* users of
   the class already have — audit the attribute on *both* sides (subject =
   escape surface, target = host→app, plus the neverallows and tunables)
   before joining; `domain` is the canonical case. — *the v2.25 completeness
   pass (2026-11-12, kernel 7.2.15, enforcing); a 24-point grant probe in a
   live `apse run` (zero denials, the audit `denied` baseline flat).*
69. **`id -Z` failing in the sandbox with "works only on an SELinux-enabled
   kernel" is a rootfs artifact, not a policy denial.** libselinux's
   "is the kernel SELinux-enabled" probe (what coreutils' `id --context`
   uses) `statfs`es `/sys/fs/selinux` and expects `SELINUX_MAGIC` (strace
   order: `statfs("/sys/fs/selinux")` → `access("/etc/selinux/config")` →
   `openat("/proc/thread-self/attr/current")`). The rebuilt rootfs leaves
   `/sys/fs` **empty** (fresh `/sys` tmpfs with only the binds the app
   needs; the cgroup2 fs is not re-rooted — decisions #12/#20, asserted by
   the 8.4 test), so the probe gets ENOENT and `id` bails out *before
   ever trying the attr read* — which would have succeeded (a sandboxed
   `cat /proc/self/attr/current` returns the app's own context; the audit
   showed zero AVCs for the whole run). Any libselinux consumer gating on
   that probe will misreport "no SELinux on this kernel" in the sandbox.
   The fix, if it ever matters: bind the `/sys/fs/selinux` mount (a
   superblock root, not a sysfs subpath — decision #18's EINVAL doesn't
   apply) into the sandbox's `/sys/fs`; the dangerous files there
   (`enforce`, `disable`, `load`) are root-owned with no group/other
   write, and the app is its real uid (uid 0 unmapped, #9), so DAC keeps
   them unwritable. — *diagnosed 2026-11-13 (kernel 7.2.15, enforcing,
   v2.25): `id -Z` in a confined `apse run`; the strace / `stat -f` /
   empty-audit triangle closed the chain.*

70. **SELinux attributes expand in `semodule -i` CIL mode, but this
   `sesearch` cannot see that expansion — verify attribute
   membership with a controlled exec or an AVC, never a sesearch
   hit/miss.** (Fedora 45, policycoreutils 3.11; verified
   2026-11-13, kernel 7.2.15, enforcing.) A probe module using the
   base policy's `exec_type` *attribute* (an attribute, not a type)
   in the *target* slot of an allow installs cleanly — `semodule
   -i` compiles it, and an undefined identifier would have failed
   the install — and the compiled policy's access vectors then
   carry the full set of tagged types. A runcon exec oracle
   confirmed the coverage: a probe process type exec'ing one
   world-exec file per type → **141/141** of the `/usr/bin` +
   `/usr/sbin` file types have `exec_type`, zero denials. The
   trap: `sesearch --allow -t <type>` against an
   attribute-valued rule returns the *raw* rule for *any* type
   (even `usr_t`, a directory type) — so in this version a
   sesearch hit or miss tells you nothing about membership; the
   `-ds` / `-dt` "match attributes" flags take no argument and
   treat the attribute name as a policy-file path (`Errno 2: No
   such file or directory`). (The object-slot form —
   `type_transition … exec_type process …` — remains the open
   question for task 8.8.) — *probe module `execprobe`, installed
   and removed the same hour; the runcon oracle is the reusable
   technique. Supplement (2026-11-13): for pure membership
   questions ("does type X carry attribute A?"), neither oracle is
   needed — `seinfo -a <attr> -x` lists the attribute's compiled
   member types straight from the loaded policy (1048 members for
   `exec_type`, including a module's own attribute additions);
   runcon/AVC remain the oracles for how a rule *behaves* (e.g. the
   object-slot transition). The runcon oracle has a subtler trap
   too: it only works on types that label real ELF files — a type
   that mostly labels data files (like `usr_t` under
   `/usr/include`) can only be probed with the few executables it
   does label, or with `seinfo`. *Supplement (2026-11-13,
   user-corrected): the `-ds`/`-dt` flags do work for the
   literal-matching direction — they are boolean flags (the Errno 2
   came from passing the attribute as a *positional* argument, which
   the CLI parses as a policy-file path), and combined with
   `-s`/`-t`/`-A` they suppress expansion of the attribute named
   there: `sesearch -ds -s domain -A -c filesystem` lists only rules
   whose source slot literally says `domain`, so you see exactly
   what broad attributes a domain actually *targets* (here:
   `base_file_type` / `base_ro_file_type` plus named types — *not*
   `non_auth_file_type`); `-dt` is the target-side mirror. That is
   the right tool for "does X grant on attribute A as written";
   for the reverse question ("does type T have attribute A?"),
   `seinfo -a <attr> -x` above remains the oracle.*
