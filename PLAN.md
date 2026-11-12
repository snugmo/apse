# apse rework: in-process sandboxing, no containers

Status: **v2.25 — fifth SELinux tuning round (2026-11-12; enforcing, kernel 7.2.15): a *proactive* completeness pass (no user-reported denial — the audit baseline stayed flat): the app's **self**-grants are re-derived as an explicit line-by-line mirror of the base policy's own `domain` self-grant set (`domain.te`'s macro expansions, spelled out literal in the CIL — raw CIL has no macros), closing the four holes the earlier denial-driven rounds had left: `dir` gained `lock`/`ioctl`/`watch` (`list_dir_perms`/`watch_dir_perms`), `lnk_file` gained `ioctl`, `file` gained `lock`/`ioctl` (`rw_file_perms` — flock on its own files, the lockfile pattern), and the fifo grant grew to the `manage_fifo_file_perms` superset (`fips_mode` is on on this box — the variant `domain.te` gives its members; `fips_mode`'s only *non-self* rule, `kernel_read_kernel_sysctls` on /proc/sys, is the one deliberate omission — the v2.24 /proc content design stays closed until a denial asks for it). The pass *investigated and rejected* joining the `domain` attribute itself (the `container_t` example — a rootless podman process is `domain`-labeled, `s0:cNNN,cMMM` — and the push on it): the attribute is two-sided and it is the *subject*-side that matters (the full audit is the CIL comment block): joining it adds every active `domain → X` rule to the app — 121 of them, 74 host types (126/76 counting the rules gated by off-tunables) — `dir`/`file`/`lnk_file` reads across `base_file_type`/`base_ro_file_type`/`security_t`/`selinux_config_t`/`var_log_t` and the user/man/font/locale families, `context translate`+its socket to `setrans_t`, `connectto`+`dbus send_msg` to `systemd_resolved_t`, `system module_request` to `kernel_t` (`domain_kernel_load_modules` is on), `process {sigchld signull}` probes to `init_t`/`sysadm_t`/`unconfined_t`/`abrt_*`/`spc_t`/`livecd_t`/`install_t`, and socket-receive grants against `unconfined_domain_type`/`netlabel_peer_t`/`ipsec_spd_t` (plus `AF_PACKET` against `unlabeled_t`) — the app→host *escape* direction, the exact asymmetry the sandbox exists to enforce (the reverse, host→app, is *intended*: the host user may signal/kill its own app, as with a rootless podman container — verified live with zero AVCs, `TERM` discarded by the pidns-init rule like in podman, `KILL` ending the run — and is *not* a reason to reject); in the *normal* sandbox most of it is gated anyway (the private pidns hides host PIDs, the rebuilt rootfs hides host inodes, nono's seccomp floor filters the sockets and the `mount`/`AF_PACKET` syscalls) — which is why `container_t` is a safe `domain` member (a privileged container *runtime* domain — 260 attributes incl. `can_load_policy`/`can_setenforce`, the svirt orchestrator of a private pidns with mapped uids — not a confined application) — but apse's primary controls are all built by apse itself, in one process tree, and the app runs as its *real* uid (no uid mapping, decision #9), so it lacks podman's uid-isolation safety net, and the SELinux module is the *independent second layer*: pre-emptively granting the full `domain` subject-side reach would disarm that backstop the moment a primary control (ns/seccomp) has a hole; the base process neverallows (FSP 45.24's `domain.te:59` `domain → ~domain:process {transition dyntransition}` + the two wider ones at :116-117) are *not* a blocker either — the installed policy enforces none of them (the module's own transitions sit squarely in their covered directions and have loaded cleanly in enforcing since v2.13 — a violation is refused at `semodule -i`) and joining adds none (the module declares no transition from `apse_app_t` as subject); the remaining reason is maintenance: (c) base drift — any future `domain.te` change (a tunable flip, a new grant) would reach the app silently, whereas the explicit mirror is audited in the enforcing-mode tuning loop (a denial → a grant). The pass also added the one `file_type` grant the denial audit could never surface: `map` on `file`/`chr_file`/`blk_file`/`lnk_file` for `apse_app_t` alone — `mmap(2)` is checked per *protection* (`read`/`write`/`execute` per prot, all already granted on the app's reachable file types — document mmaps on the state tree already worked), so the only missing case was `map` itself (a PROT_NONE address-space reservation) on the general file families: exactly the body of the base's `domain_can_mmap_files` tunable, which is *off* on this box (getsebool; the sesearch `:True` annotation is condition polarity, not value) for all 934 `domain` members (even `mozilla_t`/`mplayer_t` lack it), scoped to one type here — strictly narrower than the tunable, and content-free (a PROT_NONE mapping cannot be `mprotect`-ed to a usable prot without the corresponding `read`/`write`/`execute` on the target type). Verified zero-denial in enforcing (a purpose-built 24-point grant probe run in a live `apse run`: getpcaps, a dup'd fd, sem/shm lifecycles incl. `SHM_LOCK`, inotify `watch`, `flock`, an `O_PATH` `getattr`/readlink, RW and PROT_NONE `mmap`s of files, the full fifo `manage` set, and `ioctl` via a made-up command number — `security_file_ioctl` fires at syscall entry, before any `FMODE_PATH`/command dispatch, so it exercises the permission even on a symlink's fd; the audit `denied` baseline is flat). Two layering findings the probe documented rather than denied: `mkfifo` (the fifo `create` grant) is blocked *before* SELinux by nono's seccomp floor (decision #25, auto-reject) — a zero-AVC EACCES in the sandbox means seccomp, not SELinux — and `lnk_file:lock` (the `domain.te` shape) is unreachable by any unprivileged process on this kernel (the only fd to a symlink is `O_PATH`, and `flock`/`fcntl F_SETLK`/`F_OFD_*` reject `FMODE_PATH` with EBADF before the LSM). Deliberately *not* fixed (continuing the v2.24 deferral): fish's completion *executing* the enumerated admin tools, the `find /` class, and the metadata sweeps (`getfattr -R`; the python3 man readlink sweep). What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.24 — fourth SELinux tuning round (2026-11-12; enforcing, kernel 7.2.15): the per-type `/proc` stat grants of v2.23 are replaced by the two base-policy attributes that define exactly that surface — `proc_type` (the `/proc/*` genfs family: `proc_t`, `proc_net_t`, `proc_kcore_t`, `proc_kmsg_t`, `proc_mdstat_t`, `proc_psi_t`, `system_map_t`, …) and `sysctl_type` (the `/proc/sys/*` subtree family: `sysctl_t`, `sysctl_irq_t`, `sysctl_kernel_t`, `sysctl_vm_t`, …) — so a future `/proc` entry with a new type needs no new rule (the whack-a-mole the earlier tuning rounds did by hand; the base policy expresses the same surface as one attribute, e.g. `container_userns_t` targets `proc_type` once). The redesign follows the base policy's own expression of the surface (`kern_unconfined` gets one rule per class on both attributes): the grant is `getattr` per class per attribute (`file`/`dir`/`lnk_file` — one rule per class, because the module store's CIL reader rejects a multi-class `allow`, LESSONS #67). `getattr` is a stat that carries no content, so the attribute floor is the same safe bound the per-type `getattr` was — broadened from 7 to 26 covered types; content access (`open`/`read`) stays per-type on `proc_t`/`proc_net_t`/`sysctl_kernel_t`/`sysctl_vm_overcommit_t`/`sysctl_fs_t`/`sysctl_crypto_t`, still deliberately excluding `kcore` (kernel memory) and `kmsg` (kernel log). The one `/proc` type in neither attribute — `mtrr_device_t` (`/proc/mtrr`) — keeps a single-rule `getattr`. The alternative shape (joining a *domain* attribute, e.g. `unpriv_userdomain`, was investigated and rejected: attribute *membership* would subject `apse_app_t` to every base rule targeting that attribute, including neverallows — attribute *targeting* is the low-risk direction the base policy itself uses). Verified zero-denial in enforcing (module advanced 27→28; sandboxed `ls /proc` with every entry resolved, `ls -la /proc/self`, the `/proc/net` probes; the audit `denied` baseline is flat). Deliberately *not* fixed (continuing the v2.23 deferral): fish's completion *executing* the enumerated admin tools and the metadata sweeps (`getfattr -R`; the python3 man readlink sweep). What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.23 — third SELinux tuning round (2026-11-12; enforcing, kernel 7.2.15): user-reported `/proc` listing denials from the sandbox. (a) `ls -laZ /proc/self/` printed `l??????????` for `cwd`/`exe`/`root`: the whole `/proc/<pid>/` pident tree carries the *target process's own* context (LESSONS #45), so the app's own links are `apse_app_t:lnk_file` — a *self*-labeled object — and the existing self grant had only `lnk_file:read` (the readlink), missing `lnk_file:getattr` (the lstat that produces the target name in a listing, the #61 split); the self grant grew to `(getattr read)`, MCS-bounded in effect (a `s0:cN` subject dominates only same-category objects). (b) The *top-level* self links (`/proc/self`, `/proc/thread-self`, `/proc/mounts`) are `proc_t` by the genfs rule (a different case) and got `getattr` on the existing `proc_t:lnk_file` grant; `/proc/net` is a *relative* symlink (`self/net`) labeled `proc_net_t` — following it lands in the process's own net dir (self-labeled) whose *files* are `proc_net_t` again, so content needs `file:(getattr open read)` and `dir:(getattr open read search)` on `proc_net_t` in addition to `lnk_file:(getattr read)` on the link (read-only: the content is network state — a private netns, loopback only, in the sandbox). (c) `ls /proc` stats every top-level entry, most with their own dedicated genfs type (`sysctl_irq_t`, `proc_psi_t`, `proc_kmsg_t`, `mtrr_device_t`, `proc_kcore_t`, `proc_mdstat_t`, `system_map_t`, `sysctl_t`): per-type `getattr` only — stat, no content read; deliberately no `open`/`read` on `kcore` (kernel memory) or `kmsg` (kernel log). Verified zero-denial in enforcing (a sandboxed `ls -laZ /proc/self/` showing all pident targets, `ls -la /proc` with every entry resolved, `stat`/`head` on `/proc/net/dev`, and a pty-driven fish `cd /proc` + `cat net/dev`; the audit `denied` baseline is flat apart from a user-run python3 man-page readlink sweep — `man_t:lnk_file:read` — the same deferred class as the `getfattr` sweep). Deliberately *not* fixed (user's call, 2026-11-12, continuing the v2.22 deferral): fish's completion *executing* the enumerated admin tools (`bootloader_exec_t`, `mount_exec_t`, `rpm_exec_t`, `lvm_exec_t`, `admin_passwd_exec_t`, …) and the metadata sweeps (`getfattr -R`; the python3 man readlink sweep). What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.22 — second SELinux tuning round (2026-11-12; enforcing, kernel 7.2.15): user-reported denial classes from a confined `df`, `ls -la /dev`, and interactive fish in the sandbox. (a) `df` (even with an explicit path) `statfs`es the root of every mount it sees, and the check targets the **mounted filesystem's** type — the `filesystem` class, the `filesystem_type` attribute family (`tmpfs_t`, `device_t`, `fs_t`, `proc_t`, `sysfs_t`, `cgroup_t`, …) — so one `filesystem:getattr` attribute grant (superblock metadata: fs type, size, free — no content) covers every mount the app may stat, plus a `sysctl_fs_t` grant for df's `/proc/sys/fs/binfmt_misc` detection. (b) `ls -la /dev` printed `l??????????` for `/dev/ptmx`: the sandbox's ptmx is a relative symlink in the fresh tmpfs (decision #39's `tmpfs_t`, not `ptmx_t`), and the lstat of the link itself (`lnk_file:getattr` — the check that produces the target name) is *separate* from the readlink (`lnk_file:read`). (c) fish's completion stats every entry it enumerates in `/usr/bin` — Fedora labels most of them with per-purpose exec types (`lvm_exec_t`, `iptables_exec_t`, `systemd_systemctl_exec_t`, `fsadm_exec_t`, …), not `bin_t` — so the grant is on the **`exec_type` attribute** (the superset of every `*_exec_t`): `file:getattr`, and on the symlinks among them `lnk_file:(getattr read)`. (d) fish maps its controlling tty back to a `/dev/pts/<N>` name by enumerating the (fresh, per-instance) devpts root: `dir:open` + `read` (the LESSONS #54/#59 opendir/getdents split), not just `search`. Verified zero-denial in enforcing (`df /run`, `df -m /run`, `ls -la /dev` with ptmx showing its target, stat/readlink on per-purpose exec-type files, and a pty-driven interactive fish with completions; the audit `denied` baseline is flat). Deliberately *not* fixed (user's call, 2026-11-12): the `find /` class — thousands of `getattr` on root-level dirs and per-purpose exec types across the whole tree. What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.21 — decision #43's SELinux side refined (2026-11-12): the per-app state tree gets a dedicated module type `apse_state_t` instead of riding the `gconf_home_t` the gnome module's `HOME_DIR/\.local(/.*)?` filecon incidentally gives to *all* of `~/.local`. On this kernel (7.2) `filecon` does not label created inodes — `selinux_determine_inode_label` consults only an mntpoint default, a process `create_sid`, or a filetrans — so a named filetrans (spelled as the five-field `typetransition`; this module store's CIL dialect has no `filetrans` keyword) makes the `apse` root `apse_state_t` at creation, and the no-rule default of `security_compute_sid` (the parent's own type) makes the whole subtree inherit it; S's setxattr walk migrates a pre-module (gconf-labelled) tree once and self-heals stragglers on every confined run (the same mechanism as `apse_shim_t`), and access to the tree is explicit per-domain grants (a module type joins no base attribute — incl. the test suite's unrelabeled `unconfined_t` pipeline: `mounton` plus the full lifecycle). This pass also closed the user-reported `ps` denials inside a sandboxed foot: `open` (opendir) on top of `read` (getdents) for the `proc_t`/`sysfs_t`/`sysctl_kernel_t` dirs, a self-referential `dir:ioctl` on ps's own `/proc/<pid>` dir (MCS-bounded in effect), and `bin_t:dir open` for fish's completion enumeration — verified clean (a confined `apse run` of `ps ax`: zero denials since the reinstall, full test suite green), which completes the v2.20 open item (the confined-mode field verification of the private home; the app's home resolves into the `apse_state_t` tree). What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.20 — decision #43 landed (2026-11-11): the default profile no longer rw self-binds the real `$HOME` and XDG dirs — the app's home is now a **private per-app state tree** under `$XDG_STATE_HOME/apse/<app-id>/` (home/config/cache/data/state subdirs), bound over `$HOME` and the XDG locations: the container-era per-app home volume (persistent, disconnected from the real home and the host desktop) re-implemented as binds. The app's environment is unchanged (the redirect is invisible); `home = "host"` restores the pre-8.3 behaviour, and the profile's `rw_binds` layer on top in both modes. Per-app, not per-instance: the instance's ephemera stay in the per-instance runtime dir, and the tree is what survives between runs of the same app. The SELinux module followed (the tree is `gconf_home_t`: S's create grants, the app's `entrypoint`/`execute` on `gconf_home_t` files, the `apse_t → apse_app_t` fallback transition). Verified in the test suite: the rootfs reference test asserts a `$HOME` write lands in the per-app state tree and never the real home, the integration suite adds a hermeticity marker (real home invisible through the private `$HOME`) and a private-home write to the Landlock probe, all tests green. What's left: a confined-mode field verification of the private home (the new `gconf_home_t` grants are not yet enforcing-tested), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.19 — the 6.5.5 `serve`-label drag refinement is done (2026-11-04): the relay now tracks the client's active drag source (a `start_drag` until that source's `cancelled`/`dnd_finished`/`destroy`; a `dnd_drop_performed` does *not* end it — a "move" drop transfers its data on the drop, so those serves stay the drag's), so the `send` (serve) records on that source are labeled `selection=drag` instead of the shared `clipboard` (a `wl_data_source` is shared by the clipboard and the drag and the wire does not say which). The adjacent `read` on the stable-protocol offer stays `selection=clipboard` — the exact contrast the refinement exists to make. Verified end to end (`drag_serve_is_audited_as_drag`: start_drag → enter → receive → send → dnd_finished) and at unit level (`the_active_drag_source_lifecycle`). What's left: 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.18 — the `dbus-proxy`/`xwayland` satellites and the broker are now **field-verified in confined mode** (2026-11-04; enforcing, kernel 7.2.15; LESSONS #45-#46). The `xwayland` satellite boots Xwayland to a full session (`xserver_t:s0:cN`) — real X clients (xdpyinfo, xclock, xterm, xeyes, xrandr, xprop) through the per-instance socket, clean TERM→KILL teardown, zero denials. Closing it exposed the shape of a satellite's confined exec (LESSONS #46): the `typetransition` makes the exec *possible*; the exec-time cred hooks then check `noatsecure`/`rlimitinh`/`siginh` against the *new* SID and their denial is a *silent degradation* (secureexec flag, soft-rlimit reset toward init's soft limits, itimer clear), never an abort — the app leg never showed the triple because this policy grants `noatsecure` on `apse_t → apse_app_t`, so only the asymmetric `xserver_t` leg needed it. The real blockers were the inherited fds (displayfd socketpair, listening X socket, /dev/null dup) — `fd:use` and the socket object's `read`/`write`/`accept`/`getopt`/`shutdown` are checked against the *creator's* type (`apse_t`), and a missing `accept` masquerades as a backlog spin (`accept() failed` loop, display "up" but serving nothing) — plus the satellite's teardown signals on the transition rule. The X server's own `-auth` lifecycle (create-on-startup, unlink-on-clean-shutdown) needed create/append/write, not just read. The `dbus-proxy` sidecar gained a stale-socket probe (a SIGKILL'd predecessor left its socket; a live one is refused, a stale one cleared), and the broker was re-verified after the kernel upgrade — the LESSONS #45 premise held on 7.2.15 (`comm_write` is byte-identical: no newline strip, owning-thread-group only). What's left: the 6.5.5 `serve`-label drag refinement (the audit itself is closed), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.17 — the decision-#42 `PR_SET_PDEATHSIG` cascade is now **field-verified on both legs** (2026-11-03; LESSONS #44), and decision #42 is complete in confined mode. The field test (a `sleep` app through the full S→A→B pipeline, straced end to end): SIGKILL S → the belt delivers SIGUSR1 to A, whose handler kills B; SIGKILL A → the belt delivers SIGUSR1 into B's pidns — the strace line (`si_code=SI_USER`, `si_pid=0`) is the kernel's own marker of a pdeathsig delivery (the sender lives in the ancestor pidns), and the delivery is a kernel-internal `group_send_sig_info`, invisible to any audit exit filter — strace is the only window. In both legs the `AppKillGuard` sweep terminated whatever the belt left behind; the run ends with no process alive. The confined-mode completion of #42 landed in this pass too: `ensure_shim` relabels the `.so` to the module's dedicated `apse_shim_t` (a 7.2 `PROT_EXEC` mapping needs `file:execute`, which the confined consumers hold only on that type — LESSONS #41) and compiles it under a *pinned* exec context so the vforked `cc` stays `apse_t` (LESSONS #42); the 7.2.11 correction — the exec clear is an *unconditional* SID change in `selinux_bprm_committing_creds`, not the `secureexec`/`noatsecure` path v2.16 assumed — is baked into the module's docs. Open question (not load-bearing while the guard exists): B *survived* the belt's USR1 in the field test (it resumed via `restart_syscall` — an `SA_RESTART` action is suspected from somewhere in the Rust ELF/dynamic-linker startup that the strace filter did not record; a plain-C control child dies correctly, under and outside trace) and died on the guard's SIGKILL. Also in this pass: the sandbox's `/dev` build now creates a fresh private `/dev/shm` (a fresh tmpfs, mode 1777) — an app mapping a shm file (the `wl_shm` path) previously hit `ENOENT` (found by the `wev` windowing test). What's left: a confined-mode run of the `dbus-proxy`/`xwayland` satellites and the broker (the relay is now verified confined; they are not), the 6.5.5 `serve`-label drag refinement (the audit itself is closed), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.16 — the S-death boundary that #41's `AppKillGuard` cannot cover is now closed by the kernel-level `PR_SET_PDEATHSIG` cascade (2026-11-02; decision #42). A death of S that the guard cannot intercept (a default-terminate signal to S itself — the actual run-#1 shape) now still ends the app: A arms `pdeathsig = SIGUSR1` (not `SIGTERM` — A keeps its pre-fork TERM/INT/HUP block, and a pdeathsig that lands in a block stays *pending* forever) with a handler installed after the second fork (so B does not inherit it) that sets a flag; the delivery `EINTR`s A's blocking wait, `waitpid_retry` reports that interrupt, and A kills B (`SIGKILL`) and exits 137. B re-arms its own link (7.2 `fork` *resets* pdeathsig — it is not inherited) and, in confined mode, an `LD_PRELOAD` shim re-arms it across the exec that may clear it. The shared `apse::pdeathsig` module (`set`/`get`/`ensure_shim`) is now used by both the run pipeline (`SIGUSR1`) and the `xwayland` satellite (`SIGTERM`; signal-suffixed shim names avoid a collision in the shared per-instance runtime dir). Verified at unit level (set/get + the fork reset; plain-exec preservation; the shim re-arm; the USR1-driven teardown) — the 7.2.11 `PR_GET_PDEATHSIG` arg2-pointer and `fork`-reset semantics were confirmed against `~/src/linux`. What's left: the field verification of the cascade (SIGKILL S by explicit PID → no orphans), the 6.5.5 `serve`-label drag refinement, a confined-mode run of the `dbus-proxy`/`xwayland` satellites and the broker (the relay is now verified confined; they are not), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.15 — A run can no longer orphan the app's namespace when the pipeline dies (2026-10-30; decision #41, LESSONS #37). Run #1 — S died silently mid-run (cause never identified: no core, no journal event, no error line), A died shortly after, and the app's pidns (B is its PID 1, immune to default-action signals from outside, decision #13) ran on forever; the only trace was the sub-cgroup `rmdir` failing `ENOTEMPTY`. Both code-level holes that can produce that cascade are now closed: (a) `EINTR` was fatal in both reapers' blocking `waitpid`s (S via `?`, A via a 126 exit) — `waitpid_retry` loops on it in both (on 7.2.11 the empirically reachable interrupt set is narrow — a STOP→CONT cycle restarts the wait, a manually sent `SIGCHLD` is consumed by `wait` itself — but a reaper that must live must never die on an interrupt); (b) there was no backstop for *any* other S exit with the app alive — the new `AppKillGuard` (armed at handoff, dropped at the run's end) SIGKILLs whatever is still in the instance sub-cgroup (`cgroup.procs` is recursive: B + all descendants; the kernel's zap of a dying pidns init is not relied on, decision #14) and warns loudly only when it actually finds a live process. Field-verified by SIGKILL-ing A: the old code reproduced the orphan (S exited 137; B+child immortal), the new code left nothing. Remaining boundary (next up): a fatal signal *to S itself* kills the guard with it (`Drop` does not run on SIGKILL) — that case, the actual run-#1 shape, needs the kernel-level `PR_SET_PDEATHSIG` cascade (A←S — A never execs — and B←A — B execs, so it needs the decision-#37 restore shim). (Previous: The full chain is now verified with a *real GUI app under enforcing mode* (2026-10-30): `foot` rendered through the `--proxy` relay into live sway under SELinux enforcing, with **zero denials** across the whole boot+render cycle — the relay (`apse_t:s0:cN`), the S→A→B pipeline, and the app (`apse_app_t`), including every SCM_RIGHTS fd exchange (the wl_shm pixel pool going up, the XKB keymap fd coming down). The enforcing-mode tuning closed five classes of gap (decisions #39–#40; lessons #34–#36): devpts without `MS_NODEV` (the VFS `may_open_dev` gate, decided before any LSM); the `run` teardown sparing live sidecar sockets (the relay's `--listen` path now outlives every `run`, and the bind recreates the parent dir); the relay's *receive-side* grants (`fd:use` targets the fd's file-object SID — for a memfd, the **creator's** type — while the implied file perms target the inode's *label*, which for an anonymous fresh-tmpfs inode is the fs default `tmpfs_t`; a denial drops the fd silently and only `MSG_CTRUNC` flags it, which `ProxySocket::recv` now checks at the loss point); the fresh-tmpfs symlink label trap (`/dev/ptmx` is `tmpfs_t`, not `ptmx_t`); and the `dir` `open`/`read` distinction (fontconfig `open()`s before it `getdents()`s). What's left: the 6.5.5 `serve`-label drag refinement (the audit itself is closed — a `start_drag` is audited as a write with its own copy-out notification), a confined-mode run of the `dbus-proxy`/`xwayland` satellites and the broker (the relay is now verified confined; they are not), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.13 — Phase 8.2 is done (2026-10-29): the SELinux module is installed and tuning-looped — written directly in CIL (`selinux/apse.cil` is the single source of truth and the install artifact: `sudo semodule -i`, no `.te`/checkmodule/build step); a confined `echo`+`cat`+`ls` produced zero denials across nine consecutive runs. A follow-up `default_range` investigation corrected the MCS semantics (LESSONS #29): the per-instance `cN` isolates the instance's **processes** (a `cN` subject may only signal/ptrace/transition a same-`cN` process — a single category is incomparable with any other, *stronger* than podman's `cNNN,cMMM`), **not** its **objects** (a `dir`/`file`/`sock_file` created under the `s0` runtime parent takes the parent's low level, `s0`, via `default_range … target low`) — file-level separation is the namespaces + landlock rootfs; the "first creator pins the session dir" caveat was removed on that basis. The same pass found the `signull` (kill -0) gap: not in the base mlsconstrain and unfixable in a module CIL (LESSONS #33), so `terminate_app`'s kill -0 probe is not category-scoped. 8.4 (the integration test suite) and 8.5 (the threat-model review, re-checked against these findings) are done (2026-10-24). The full chain is verified at probe level: a sandboxed `wayland-info` driven through the `--proxy` relay into the live sway (2026-10-24). What's left: a real GUI app through the relay (ideally under enforcing mode — the relay/satellites/broker have not yet run in confined mode), the 6.5.5 `serve`-label drag refinement (the audit itself is closed — a `start_drag` is audited as a write with its own copy-out notification), and 6.4 (parked until a released systemd ships `PIDs` in `StartTransient`). (Previous: v2.12 — Phase 7.3 is done (2026-10-24): `apse xwayland` — the host-side per-instance Xwayland satellite (sway's spawn pattern: sidecar-created+listened `-listenfd` socket in the per-instance runtime dir, `-displayfd` readiness gate with display-number cross-check, `-auth`, `-nolisten tcp`, `-rootless`). Verified end-to-end (a real X11 client connects to the instance socket) and on both teardown paths (SIGTERM; SIGKILL with the SELinux-pdeathsig restore shim — decision #37). (Previous: v2.11 — Phase 7.2 is done (2026-10-24): `apse dbus-proxy` — the host-side per-instance `xdg-dbus-proxy` sidecar (direct spawn, not a unit; public `bus.sock` in the per-instance runtime dir, owner-only; see/talk/own/call/broadcast rules forwarded verbatim, fail-closed once any is present). The child's lifetime is a *fd*: a private socketpair handed over as `--fd=3` (non-CLOEXEC — `execve` closes CLOEXEC), so even a SIGKILL'd sidecar tears the proxy down (decision #36); verified pass-through + SIGTERM + SIGKILL teardown. (Previous: v2.10 — for the in-process architecture (8.1, 2026-10-24): the S→A→B pipeline, the rebuilt rootfs, the nono policy, the relay/broker/decider, the layered containment table, install/profiles/the per-app relay recipe, verify-your-setup, and the residual-risk list. The zbus 6 migration (`6725560`) landed with it. Phase 5.5 is done (2026-10-24): Firefox ran through the full S→A→B pipeline on this desktop — the window reached the compositor, network egress worked, and a SIGTERM tore it down cleanly; it also confirmed decision #32 (the supervisor services *every* trapped notification, so multi-process apps that inherit the filter don't deadlock). The code-quality sweep is done (2026-10-24): rustfmt/clippy/check clean, the dead `security_context.rs` module removed, the broker's public API tightened, the container-era test fixtures and `Mode A/B` / quadlet comments purged, and the unsafe surface audited (all ownership transfers and the one `transmute` are SAFETY-documented; 192 tests green). The optional 7.3 xwayland satellite and Phase 8's 8.2 and 8.4–8.5 (the SELinux policy, the integration test suite, the threat-model review) remain, plus the full chain (a sandboxed app through the proxy into sway) and the drag-and-drop audit (6.5.5)))))))))))))))**

The podman/quadlet layer is deleted (`0c842cf`); the remaining
container-era artifacts (`docker-bake.hcl`, `systemd/`, `selinux/`) are
deleted in the same rework. Containment moves into the `apse` binary
itself: it becomes a CLI tool that, per app, creates Linux namespaces,
builds a private rootfs, applies landlock + seccomp via the
[`nono`](https://docs.rs/nono) library, and `exec()`s the app — with
`apse` itself staying on the host as the **supervisor** (tagged Wayland
socket, seccomp-notify handler, signal forwarding, systemd integration).
systemd integration and SELinux policy are written **from scratch** in
later phases.

---

## 1. Target architecture

```
host user session (uid 1000, sway)
│
├── apse run --app-id rustrover -- <cmd>  ← supervisor, unsandboxed, host namespaces
│   │   - optional: registers itself in a systemd user SCOPE via D-Bus
│   │     (StartTransientUnit, PIDs=[self] — decision #35) — or plain
│   │     cgroup fallback
│   │   - tagged Wayland socket   (wp_security_context_v1, as today)
│   │   - services the app's seccomp-notify fd (decisions #22–#25)
│   │   - sd-notify, signal forwarding, waits on child
│   │
│   └── fork ──► app process      ← the sandbox, runs as UID 1000 (not root)
│       unshare user   (single-extent map: identity stays 1000, full
│                       ns cap set, 0 unmapped — decision #10)
│       unshare mount  → build the rootfs (ns-local CAP_SYS_ADMIN)
│       unshare pid → ipc → uts → cgroup → net
│       nono: landlock + seccomp
│       execve  (app is PID 1 of its pidns)
└── apse dbus-proxy / apse xwayland — host sidecars (Phases 7.2/7.3)
```

Compared to the container era:

- **Gone:** pods, containers, quadlets, Containerfiles, image layers, pod
  networks, SELinux CIL for `container_t` sidecars, MCS, `systemd-run`
  shell-outs.
- **Same in spirit:** unprivileged user namespace; private filesystem view;
  per-instance runtime dir under `$XDG_RUNTIME_DIR/apse/<instance>/`;
  tagged Wayland socket + compositor policy; GPU render nodes by direct
  device access; (later) filtered session bus.
- **Different:** the app runs as **uid 1000, not root**, inside the
  namespace (see §3.2) — stronger than rootless podman, and friendly to
  apps that refuse to run as root; landlock + seccomp via `nono`;
  cgroup ns under a systemd *scope* created over D-Bus (no `systemd-run`).

The supervisor stays *outside* the namespaces deliberately: it needs host
access (compositor socket, session bus, cgroup files) and it is the process
the seccomp-notify fd belongs to.

## 2. nono 0.80.0 — verified API surface

Checked against the published crate source before writing this plan.

- **Linux backend = Landlock LSM** (ABI detection via `Sandbox::detect_abi()`;
  network rules need ABI ≥ v4 → kernel ≥ 6.7; Fedora 45 is fine). Older
  kernels fall back to seccomp-based network filtering
  (`apply_auto()` returns the fallback state).
- **`CapabilitySet`** is the policy object:
  - fs: `allow_path/allow_file(path, Read|ReadWrite|…)`, deny-by-default
  - unix sockets: `allow_unix_socket(_dir/_subtree)` — tagged wayland
    socket, (later) dbus-proxy sockets, ssh-agent, X11
  - network: `block_network()`, `set_network_mode(Blocked|AllowAll|ProxyOnly)`,
    `allow_tcp_connect/bind`, `allow_localhost_port(_range)`, `allow_https()`
  - further knobs: `set_signal_mode()`, `set_process_info_mode()`,
    `set_ipc_mode()`, `with_resource_limits()`
- **`Sandbox::apply_auto(&caps)`** applies to the *calling process*
  (irreversible; inherited across `execve`). `prepare_*`/`install_*`/
  `apply_external()` primitives also support post-fork choreography
  (supervisor prepares the BPF, child installs) — verify which pattern to
  use in Phase 4.
- **seccomp** is built by nono itself (raw BPF, no libseccomp): a static
  filter (network block, arch guard) plus a **SECCOMP_RET_USER_NOTIF**
  filter routing `openat/openat2`, `bind/connect/sendto/sendmsg/sendmmsg`
  to a supervising process.
- **Supervisor IPC** (`nono::supervisor`): length-prefixed messages over a
  Unix socket, `SO_PEERCRED` auth, `SCM_RIGHTS` fd injection; pluggable
  `ApprovalBackend` (we start with an auto-deny `PolicyApproval`).
- License: Apache-2.0 — compatible with this repo's AGPL-3.0.

## 3. Sandbox construction (what the child does)

### 3.1 User namespace + the non-root credential model

Two kernel rules fix the shape of the map (verified in the v7.2.11
source — `kernel/user_namespace.c` — and empirically on this machine):

- `uid_map`/`gid_map` accept **exactly one successful write**
  (decision #9).
- An **unprivileged** creator may write **only a single extent of
  count 1 whose in-ns id equals its own uid/gid**:
  `new_idmap_permitted()`'s fast path requires exactly that (the ns
  owner is the creator's euid, set by `create_user_ns()`); anything
  larger needs `CAP_SETUID`/`CAP_SETGID` in the *parent* ns, which we
  don't have. Two extents sharing a parent id would in any case be
  rejected by `mappings_overlap()` — so the old two-entry
  `0 → self; self → self` map is **EINVAL** on modern kernels
  (decision #10). bwrap reaches multi-extent maps through the setuid
  `newuidmap`/`newgidmap` helpers; we deliberately don't.

So the map is the single extent `<real uid> → <real uid>` (and the
same for gid), and `setgroups=deny` is written first, before the maps:

```
<real uid> → <real uid>   (the app's identity — the in-ns uid from the
                             start; 0 is simply not in the map)
```

Sequence (in the forked child — apse itself stays outside the ns):

1. `unshare(CLONE_NEWUSER)`; write `setgroups=deny`; **one write** of
   `uid_map`/`gid_map` (the single extent above).
2. **Mount phase**: unshare the mount ns and build the whole rootfs
   (§3.3). We hold **the full ns capability set** throughout:
   `set_cred_user_ns()` grants the creator CAP_FULL_SET in the new ns
   and nothing on this path clears it (the 7.0 credential rework moved
   the setuid cap-clearing; empirically CapEff is still
   `000001ffffffffff` after the map write and after a no-op
   `setresuid(self)`). That is safe *by construction of the map*:
   every ns-local capability (dac, kill, ptrace, mount, …) only has
   effect on objects and processes inside our namespaces — and the
   only identity mapped into them is ours — so at exec time we hold no
   privilege beyond running the same command unconfined as the same
   user. The hard privilege boundary is nono's landlock + seccomp
   filter (Phase 4), which additionally denies the
   `setuid`/`setgid`/`setres*`/`sete*` family.
3. The remaining namespaces (§3.2).
4. **nono apply** (landlock + seccomp), then **`execve()` the app**.

The identity is locked **by the map itself**: the in-ns id is the real
uid from the start, in-ns `0` is unmapped, so no `set*uid` call can
ever move it (`setresuid(0)` is EINVAL; the only other mapped value is
the same one), and a second map write is impossible (write-once).
`verify_locked()` asserts exactly this before the exec and aborts
(exit 126) if anything is off.

A subuid range for file *ownership* would need a second extent and
hence a setuid helper (`newuidmap`); deferred (decision #10). Files
the app writes are owned by its real uid on the host — identical to
running unconfined. The app sees itself as its real uid (1000): no
root-in-ns behaviour.

### 3.2 Remaining namespaces (order after the mount phase)

- **PID ns** — the intermediate fork A unshares the pidns, then forks
  once more: the app (B) is **PID 1**. A stays in the *parent* pidns,
  reaps B, and exits with B's status — the teardown we actually rely on
  (7.2's zap is a no-op for surviving members, #13/#14). `apse` stays
  outside both and sees A as a normal child for signalling/reaping.
- **IPC ns** — fresh (private System V + shm view).
- **UTS ns** — `sethostname("apse-<app>-<instance>")`.
- **Cgroup ns** — created and entered **before** unsharing, which
  must happen **before** the rootfs build (the self-bind of `/`
  makes cgroup2 read-only): the instance sub-cgroup is `mkdir`'ed at
  the full path and entered via `cgroup.procs`, *then*
  `unshare(CLONE_NEWCGROUP)` — so the ns root **is** the instance
  cgroup and the app sees `0::/` (#20). The supervisor rmdirs the
  empty sub-cgroup on exit. The cgroup2 fs itself is not re-rooted
  on 7.2 (#12); `/sys/fs` is left empty.
- **Network ns** — per-app mode, decided in §5 (default: *shared* host
  netns + nono filtering; `--network=none` = bare new netns).

### 3.3 Rootfs construction (mount phase, as ns-root)

| Target | How | Notes |
|---|---|---|
| `/` | one-shot recursive self-bind (ro flag unattainable — #21) | new layer under the overlays below; read-only *semantics* for the app come from its real uid + nono (Phase 4); masks last |
| `/dev` | fresh tmpfs + **bind-mount** of the host nodes `null`, `zero`, `full`, `urandom`, `random`, `tty`; `/dev/ptmx` is a **symlink** into the fresh `devpts` instance (a host bind would hand the app the host's pty master); a fresh private `/dev/shm` tmpfs (mode 1777 — the `wl_shm` path) | bind-mount, not mknod: nodes keep their canonical genfs SELinux labels (`null_t`, `urandom_t`, …) so the confined domains need plain standard `open/read/write` rules; matches the rootless-runc approach. Clear error if a host node is missing. |
| `/dev/pts` | `mount devpts -o newinstance` | fresh instance, isolated from host pts |
| `/dev/dri` | bind from host | GPU; user must be in `render` group (same requirement as rootless podman); `--no-gpu` skips |
| `/proc` | fresh procfs mount | allowed in an unprivileged user ns (namespaced view); verify on target kernel (Phase 2) |
| `/sys` | fresh tmpfs + binds of `devices/`, `class/` (ro unattainable — #21) | only the sysfs *mount root* is unbindable (#18); these subpaths cover DRM/PCI discovery |
| `/run` | fresh tmpfs | per-instance dir: tagged wayland socket, supervisor socket, (later) dbus-proxy socket, (optionally) ssh-agent socket. Its *content* is the host's per-instance runtime dir, **carried into the step-1 scratch before this mask** and bound in from there — binding the host path directly here would silently hit this fresh tmpfs's own empty stand-in dir (#28) |
| `/tmp` | fresh tmpfs | `size=` from profile |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc` | ro-binds | `/etc` as-is; passwd/group map consistently through the uid/gid maps |
| app dir | ro-bind (e.g. `/opt/rustrover`) | path from the app profile |
| app home and XDG dirs | default: binds of the per-app state tree over the standard locations; `home = "host"`: rw self-binds | **decision #43**: the default is a **private per-app** tree at `$XDG_STATE_HOME/apse/<app-id>/` (home/config/cache/data/state subdirs) bound over `$HOME` and the XDG locations — the container-era per-app home volume (persistent, disconnected from the real home and the host desktop). The tree is carried into the step-1 scratch (its host path sits under the home that this step replaces — #28's trap); binds go home → config → cache → data → **state last** (state may nest under data). The app's env keeps its historical XDG strings — the redirect is invisible. `home = "host"`: the real dirs rw self-bound (the pre-8.3 behaviour). The profile's `rw_binds` layer on top in both modes. |
| masked | bind empty tmpfs over | `/root`, `/home/*` (except mapped ones), `/boot`, `/var`, `/srv`, `/media`, `/mnt`, `/opt/*` (except the app), anything the profile marks private |

Then `chroot()` to the assembled root. The **host** Wayland socket is
deliberately *not* visible to the app — only the tagged one — so the app
cannot bypass the security context.

All of this happens **before** nono is applied, so seccomp never needs to
permit `mount`/`mknod`/`unshare` for the app.

## 4. systemd integration (least-intrusive: one in-process call, no `systemd-run`)

**Revised 2026-10-23 after hands-on verification on the Fedora 45 target
(#35):** the varlink-first plan is *inverted*. Every released systemd
(≤ v261) lacks a varlink path that can attach PIDs to a scope, so
**D-Bus on the session bus is the primary tier** — and it works on all
distros that have a user systemd, old and new.

`apse run` attempts, in order, and logs which tier it landed on:

1. **D-Bus to the user systemd** (`org.freedesktop.systemd1.Manager`
   `StartTransientUnit` over the session bus; `zbus`, driven on a
   fresh local tokio runtime per call — see `src/systemd.rs`):
   unit `apse-<app>-<instance>.scope`, mode `replace`,
   properties `{ PIDs: [self] }` (**type `au`**, property name
   `PIDs` — that has been the name since scopes exist, v252).
   `systemd` moves **apse itself** into the new scope's cgroup.
   Then the existing #12/#20 flow is unchanged: A captures *its*
   current cgroup before unsharing (now the scope's) and mkdirs the
   instance sub-cgroup below it. **Verified on target:** the scope
   dir is *user-owned* (the user-session subtree
   `user.slice/user-<uid>.slice/user@<uid>.service/` is delegated to
   the user — all dirs/files uid-owned, so no `Delegate=` is needed
   and the user can `mkdir`/write inside the scope freely); the scope
   lands in `app.slice`; a child cgroup created by the user inside it
   accepts the app's pid; the scope **auto-stops and is removed
   recursively** (scope + children) when the last member (the
   supervisor, which exits last) leaves.
   Deliberately **no `StopWhenUnneeded`**: in v261 it is actively
   harmful for scopes (`unit_is_unneeded` stops any active jobless
   scope immediately — verified: scope vanished in the same second,
   member still alive). The empty-cgroup auto-stop already gives the
   desired "dies with the instance" lifecycle, and that has been
   stable forever. Stale-unit handling: on `UnitExists` (a loaded
   unit of the same name) → `StopUnit` best-effort → retry once.
2. **Raw-cgroup fallback (no session bus / no user systemd / call
   failed):** no unit at all. The instance sub-cgroup is created
   under the cgroup apse is currently in (user-slice leaves are
   writable by the user; creating child cgroups under a populated
   cgroup is legal in cgroup v2 — the no-internal-process rule only
   blocks enabling *controllers* there, which we don't need for a
   cgroup ns), and proceed. Documented degradation: no unit
   visibility/accounting.
3. **Future — varlink (when it can do this):** `io.systemd.Unit.StartTransient`
   exists since v261 but only for *services* (`ID`/`Description`/
   `Service{Type,ExecStart,RemainAfterExit}`); `SetUnitProperties`
   takes `Markers` only. A scope *without* PIDs cannot even start
   ("Scope has no PIDs. Refusing" — verified on target). A scope
   context with `PIDs` exists only on `main` (commit abde7e80d0,
   2026-10-16; after v262 — will land in a future release). Revisit
   the tier order then: varlink needs no session bus at all.

`cgroup.subtree_control` writes (resource limits for the `app` sub-cgroup)
are a later optional extension, not required for namespacing to work.
The user-session delegation chain on Fedora 45 permits enabling
`cpu`/`memory`/`pids` in user-owned cgroups (the user manager's
`user@<uid>.service` has them in its `subtree_control`); `io` is not
delegated, so no `io` limits from inside the session.

## 5. CLI design & network decision

```
apse run      [OPTIONS] -- <command> [ARGS...]  # full pipeline, execs the app
                                                 # (--app-id selects the profile)
apse wayland  [OPTIONS]                        # tagged socket only
                                                 # (tag-and-park), or
                                                 # --proxy: the mode A relay
apse broker   [OPTIONS]                        # the prompt broker daemon
apse decide   [OPTIONS]                        # list / resolve pending
                                                 # prompts
apse dbus-proxy [OPTIONS]                      # host D-Bus sidecar (7.2)
apse xwayland   [OPTIONS]                      # host X satellite (7.3)
# later phases: profile show, status/stop
```

Key options: `--app-id`, `--instance-id`,
`--network={shared|none}`, `--gpu/--no-gpu`, `--wayland` with
`--listen <path>` / `--socket-activation`. There is no `--config` flag
(profiles are a fixed path) and no verbosity flag — logging is
`RUST_LOG` via `env_logger`.

**Network (decided):** `shared` (default) = the *shared* host netns,
currently **unfiltered** (egress allowed, no bind — matches the old
"egress allowed" behaviour at zero plumbing cost; nono's network
filtering would cover it but is a later phase — see the `cli.rs`
comment). `none` = a bare netns with only loopback, brought up.
Private-netns options (veth, pasta/slirp4netns) are a later hardening
phase, out of scope for now.

**App profiles** replace the quadlet drop-ins: TOML in
`~/.config/apse/apps/<app-id>.toml` (ro binds, rw binds, masked paths,
env vars, network mode, gpu, tmp size, home mode — decision #43:
`"private"` (default) or `"host"`). New deps: `nono` (pinned),
`toml`, `serde`, and `zbus` (Phase 6, D-Bus tier).

## 6. Decisions log

| # | Question | Decision |
|---|---|---|
| 1 | Network default | Shared host netns + nono filter; `--network=none` for air-gapped; veth/pasta later |
| 2 | UID inside ns | **Non-root (1000)** via a mapping that includes the real uid (§3.1, revised by #9, #10); subuid range deferred (#10) |
| 3 | D-Bus proxy | **Deferred** to a later phase (after namespacing works) |
| 4 | Xwayland | **Deferred** to a later phase |
| 5 | App distribution | *Open* — run host-installed apps (`/opt/<app>` ro-bind) for now; GPG/fetch story undecided |
| 6 | `apse wayland` subcommand | Keep (already tested; no unit file in repo anymore) |
| 7 | Cleanup | Delete `docker-bake.hcl`, `systemd/`, `selinux/` (done this round). **`Dockerfile` still to decide** — it only existed to build the container image; propose deleting it in favour of a plain static build recipe. |
| 8 | systemd integration | In-process unit-start call: **D-Bus session-bus `StartTransientUnit` primary** (`PIDs=[self]`), raw-cgroup last resort, varlink a future tier — §4, #34/#35 |
| 9 | `uid_map` write-once | **Confirmed.** Modern kernels permit exactly one write to `uid_map`/`gid_map` (verified in the v7.2 stable source and current master). The original design (single write of `0 self` + `self self`) turned out to be invalid — superseded by #10, which keeps write-once but makes the map a single extent. |
| 10 | Map shape: single extent | **`<self> <self> 1`** (one extent, uid and gid). Kernel constraints: write-once (#9); an unprivileged creator may only write one extent of count 1 equal to its own uid/gid (`new_idmap_permitted()` fast path); two extents sharing a parent id are rejected by `mappings_overlap()` — so the two-entry `0 self; self self` map is EINVAL (bwrap uses the setuid `newuidmap` helper for more; we don't). Consequences: the identity is the real uid from the start, 0 is unmapped (`setresuid(0)` is EINVAL), the full ns cap set is held at exec — safe by construction of the map (§3.1) — and locked by nono in Phase 4. Subuid range for file ownership deferred (needs a setuid helper). Verified on 7.2.11-300.fc45; §3.1 rewritten; Phase 1 done. |
| 11 | Target release | **Fedora 45** (machine upgraded; running 7.2.11-300.fc45). Kernel series 7.x; Landlock ABI ≥ v4 and unprivileged userns — verified on this machine (Phase 1.4). |
| 12 | Cgroup ns view on 7.2 | The **cgroup2 filesystem is not re-rooted** by the cgroup ns — only `/proc/*/cgroup` is namespaced. So the child captures its full cgroup path *before* unshare, unshares, then `mkdir`s the instance sub-cgroup at that full path and moves in via `cgroup.procs`. The supervisor `rmdir`s the empty sub-cgroup when the instance dies (best-effort). `/proc/self/cgroup` inside shows the clean relative path. |
| 13 | pidns-init is unkillable | The first process of a pidns carries `SIGNAL_UNKILLABLE`: default-action signals are ignored, *except* SIGKILL/SIGSTOP from an ancestor pidns. Our app **is** pidns-init, so the shutdown protocol (Phase 5.4) is **SIGTERM, then SIGKILL fallback** — never wait for a TERM. |
| 14 | pidns teardown on 7.2 | When the ns leader exits, `zap_pid_ns_processes()` **does run** (`disable_pid_allocation()` proven), but on 7.2.11 the SIGKILL to surviving members is empirically a **no-op** — strays reparent, they don't die. We therefore don't rely on it: A (ns leader, in the *parent* pidns) reaps B and **exits by choice**, so nothing is left behind; exit codes propagate through A reliably (verified 5/5 for 0/42/137, incl. `128+sig` for signals). |
| 15 | `/sys/class/net` is global | On 7.2 it lists interfaces of **all** netns (a global sysfs tree) — `unshare --net` still shows the host's. Per-netns verification uses `/proc/net/dev` (per-reader view) and netlink (`ip link`); the network tests do exactly that. |
| 16 | Mount-ns naming/propagation quirks | The mount-ns symlink is `ns/mnt` (not `ns/mount`); `/proc/self/ns/` also contains `pid_for_children`/`time_for_children` entries. In mountinfo the word `private` is **omitted** (it's the default; only `shared:`/`slave:`/`unbindable:` tokens appear — host `/` shows `shared:1`). "View is private" is therefore asserted by *absence* of propagation tokens, gated on a host precondition that `/` is shared. |
| 17 | The mount-ENOENT "flake" | **Not a kernel bug.** The mount test passed a non-NUL-terminated Rust `&str` to `mount()`/`umount()`; the kernel over-reads until a NUL, and the byte after the heap buffer is usually zero (worked) but occasionally not (garbage-suffixed path → ENOENT, sticky, invisible to `stat()`, stale dir left behind). v7.2 dcache/namei audited and exonerated (incl. the 98b6cf102b35 negative-dentry fix — a real but different bug). Fixed `6d255d1`. Rule: **every path handed to a C interface is NUL-terminated** (the `cstr` helper in `src/sandbox/mounts.rs`). |
| 18 | Binding mount roots | Binding the **mount root** of devtmpfs/sysfs/ext4 (e.g. `/dev`, `/sys` themselves) is EINVAL unprivileged on 7.2.11; any **subpath** or file binds fine. Hence `/dev`/`/sys` are rebuilt as fresh tmpfs + subpath binds (the scratch dir carries the node files out of the tree before the self-bind). |
| 19 | `mknod` unprivileged | Unprivileged `mknod` of device nodes is EPERM on 7.2.11 (SELinux enforcing). `/dev` nodes and `/dev/dri` are therefore **bind-mounted** (canonical genfs SELinux labels preserved), never mknod'd. |
| 20 | Cgroup ns root | The ns root is the unsharing task's cgroup **at unshare time**, so the instance sub-cgroup must be entered *before* `unshare(CLONE_NEWCGROUP)`: the app sees `0::/` (its own cgroup is the root; 7.2 renders it with a trailing slash). The Phase-2 order (unshare → move) rooted the ns at the session cgroup (`0::/app-N`) and is corrected; it must still precede the rootfs build (cgroup2 goes ro with the self-bind). |
| 21 | ro-binds are unattainable | On 7.2.11 `MS_BIND\|MS_RDONLY` **silently drops the ro flag** on a bind of a foreign superblock (probed on `/`, on files, and in both one-shot and make-private variants); the two-step bind → `MS_REMOUNT\|MS_RDONLY` is EPERM (the sb's `s_user_ns` is init — we can remount only our *own* fs). §3.3 corrected: `/` and the `/sys` subpaths are plain binds; read-only *semantics* for the app come from its real uid (root-owned trees unwritable) plus the nono landlock/seccomp policy (Phase 4). The test's former `ROOTWR` probe was a false positive (EACCES ≠ EROFS) and the `/proc/mounts` `head -1` read the *bottom* of the mount stack — the topmost entry is the last line. |
| 22 | One notify listener per thread | Linux allows a single `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter per thread, so nono's AF_UNIX mediation filter (traps all `connect`/`bind`/`sendto`/`sendmsg`/`sendmmsg` — the family is checked in userspace, BPF cannot dereference) and the openat-logging filter must be one combined program (`PreparedSeccompNotifyFilter::with_openat_notifications`). Consequence: every `sendmsg` of the app (incl. all wayland/TCP traffic) is a supervisor round-trip — the supervisor must stay a tight, responsive loop or the app stalls. The filter is installed **before** `apply_landlock` (nono's requirement: the supervisor must see paths Landlock would block). |
| 23 | Notify-fd handoff without SCM_RIGHTS from B | B's `sendmsg` is trapped by its own filter, so B cannot hand the listener fd to S via `SCM_RIGHTS` after install. Handoff: B writes the listener's *fd number* to a pre-made B→A pipe; A (unfiltered, B's parent, same uid) does `pidfd_open(B)`+`pidfd_getfd(num)` to take its own copy, then sends it to S over a pre-made S↔A socketpair. All three channels are created in S **before** the first fork and distributed at the forks (A closes the S-side copies, B closes the A-side copies). A dead B (zombie has no fd table) → handoff fails → S falls back to plain `waitpid` (landlock still enforced). |
| 24 | Landlock needs explicit ancestor grants on Linux | A landlock rule is a default-deny floor: to reach a granted subtree the app also needs refer/traverse on every ancestor. nono's `path_metadata_dirs` (ancestor metadata grants) is macOS-only — on Linux the policy itself must grant `/` Read (and any other ancestor chains). Consistent with the current rootfs: the self-bind of `/` already shows the app every top-level directory, so Read-on-`/` adds no visibility. |
| 25 | Supervisor decides (auto-deny), never expands | The supervisor's role in Phase 4 is mediation+logging, not expansion: openat/AF_UNIX notifications are answered continue (allowlisted) or EACCES (denied + logged); there is no fd injection, no approval flow. Abstract/unnamed AF_UNIX sockets are denied (nono's default for pathname mediation) — GUI apps that use abstract-socket IPC (e.g. Chromium-style) may need a per-profile relaxation, to be added if Phase 5's E2E hits it. |
| 26 | Deterministic handoff: the verdict pipe | The seccomp listener is allocated `O_CLOEXEC` in B's table by the kernel (`get_unused_fd_flags(O_CLOEXEC)`, `kernel/seccomp.c`), and `pidfd_getfd` on B succeeds only while B is still dumpable — i.e. *pre-exec* (after exec the credential change fails `task_still_dumpable` → `EPERM`). If B started execing while A was still extracting, the dynamic loader's `openat`s would pile up on the dying listener: `seccomp_notify_free` completes every pending notification with `-ENOSYS` (observed: `Error 38` on `libtinfo.so.6`). Hence B blocks on an A→B **verdict pipe** before exec (`1` = exec, `0` = exit 126 — never an unsupervised exec); A sends it only after the extract + `SCM_RIGHTS` to S have completed. Two close-order invariants: B must *inherit* the verdict read end, so A closes its copy only *after* the second fork (closing it before the fork left B polling a dangling fd number — the "hang" that gdb showed as B-in-poll/A-in-wait4); and A ignores `SIGPIPE` after the fork, because a failure-path verdict can hit a pipe whose reader is already gone and must not kill A before it reaps B. |
| 27 | nono's three-stage prepare/apply — the filter must never precede landlock's *prepare* | nono's `apply_landlock` calls `open_path_rule` → `open(O_PATH)` for every rule path. Installing the seccomp-notify filter *first* traps those opens: B blocks in a notification wait with no supervisor running yet — a hard deadlock (observed: 300 s timeout, zero output). The working order is nono's own prepare/apply split: `prepare_landlock_with_abi` (opens all rule paths, while unfiltered) → install the combined filter → `apply_raw` (consumes the prepared fds; opens nothing). #22's "the filter must precede landlock" survives as *the filter must precede landlock's **apply***. |
| 28 | The rootfs scratch lives on `/var/tmp`; the runtime dir is carried before the `/run` mask | The scratch must stay resolvable through every build step, so it cannot sit under any masked tree. The old location (inside the per-instance runtime dir) is under `/run` for the default `XDG_RUNTIME_DIR=/run/user/<uid>` — and a bind *source* resolved after the fresh-`/run` mask hits the fresh tmpfs's empty stand-in directory: a **silent self-bind no-op** that never crosses to the host (writes "succeed" into the throwaway tmpfs; the app-side socket is invisible). New layout: the scratch is `/var/tmp/.apse/<inst>` (mode 0700, not in the capability set; hidden from the app by the `/var` mask of step 8 *and* the Landlock floor), and the per-instance runtime dir is carried into it in step 1 — the only point where its host path is still resolvable — then bound onto the fresh `/run`'s instance dir in step 5. S removes the scratch (and its parent) on exit. |
| 29 | Raw pidfd syscalls: explicit zero flags; the *host* pid is the right argument | `libc` 0.2 (gnu x86_64) exposes `SYS_pidfd_open`/`SYS_pidfd_getfd` as numbers only, so they are called via `syscall(2)`. The kernel does `if (flags) return -EINVAL` for both, and a short `syscall(2)` call leaves the flags register uninitialised → spurious `EINVAL` (observed on `pidfd_open`). Pass `0` explicitly. Also, `pidfd_open` resolves the pid *globally* (`find_get_pid` → `find_vpid`, the init-namespace hash), so A — inside the fresh pidns — must pass B's **host** pid, which is exactly what `fork()` returns (`clone` returns `pid_vnr` = `level[0].nr`, never the caller-namespace-local pid; B's local pid `1` would be the wrong argument). |
| 34 | Varlink first, D-Bus as fallback | `apse run` starts the scope via **Varlink** `io.systemd.Unit.StartTransient` on the *user* manager socket (`/run/user/<uid>/systemd/io.systemd.Manager`) — JSON over a unix socket, one request/response, no polkit, hand-rolled (~60 lines, no dep on the primary path). Requires **systemd ≥ 261** (`StartTransient` added in commit 913b81735e; the `io.systemd.Unit`/`io.systemd.Manager` skeletons from 258). Distro coverage (pkgs.org check, 2026-10): Ubuntu 26.10, Fedora 45+, Arch, OpenSUSE Tumbleweed, Wolfi. Older stacks (Debian 13, **Ubuntu 26.04 LTS**, RHEL/EPEL) fall back to **D-Bus** `org.freedesktop.systemd1.Manager.StartTransientUnit` on the session bus (`zbus` — chosen over `dbus` 0.9: zbus is the maintained, stable, widely-used crate). Tier order at runtime: varlink → D-Bus → raw-cgroup; the outcome is logged. The `varlink` crate (13.0.0) was considered but not adopted for the one-shot call. |
| 35 | D-Bus primary, varlink deferred (supersedes #34) | Hands-on verification on the Fedora 45 target (systemd 261) overturned the varlink-first plan. (a) `io.systemd.Unit.StartTransient` exists since 261 but is **service-only** (`ID`/`Description`/`Service{Type,ExecStart,RemainAfterExit}`); `SetUnitProperties` accepts `Markers` only; a scope created without PIDs **refuses to start** ("Scope has no PIDs. Refusing"). A scope context with `PIDs` (json pidref) exists only on `main` (abde7e80d0, 2026-10-16 — after v262), so no *released* systemd can do the operation via varlink. (b) D-Bus `StartTransientUnit` works on every user-systemd stack (scopes since v252), needs no polkit on the session bus, and the exact call is: unit `*.scope`, mode `replace`, properties `{ PIDs: <au> [self] }` — property name is `PIDs` (since v252), value an array of uint32; reply type is `(o)`, not `(uo)`. (c) `StopWhenUnneeded=true` is **harmful** on v261 scopes: `unit_is_unneeded()` stops any active, jobless, unpinned scope immediately (verified: scope removed in the same second, member alive, cgroup `(deleted)`). Not needed anyway — a scope auto-stops and is removed **recursively** when its last member leaves (verified: supervisor in scope, app in a user-mkdir'd child; supervisor exits last → whole subtree gone). (d) `Delegate=` is unnecessary: the entire user-session cgroup subtree (`user.slice/user-<uid>.slice/user@<uid>.service/`, incl. manager-created scopes) is **owned by the user** (delegation of `user@.service` chowns it), so the user can `mkdir`/write `cgroup.procs` inside the scope without any unit-level delegation. The user manager also lands transient scopes in `app.slice` (not directly under `user@.service`) — hence the instance sub-cgroup's parent is read from `/proc/self/cgroup` after the call, never assumed. Net: D-Bus (`zbus`, driven on a fresh local tokio runtime per call — never the process-global `OnceLock` runtime, which is dead in a forked child; see `src/systemd.rs`) is the primary tier for all distros (incl. Ubuntu 26.04 LTS, Debian 13 — the very distros that motivated the fallback); varlink becomes a future tier (6.4) once a release ships scope-with-PIDs. The raw-cgroup path remains the last resort (and is what A already does in #12/#20 — the only change is that S's D-Bus call moves S (and thus A's inherited cgroup) into the scope before the forks). |

| 36 | The D-Bus sidecar's lifetime is a *fd*, and that fd must be *non*-CLOEXEC | `apse dbus-proxy` spawns `xdg-dbus-proxy` (0.1.9) as a child it owns (signalfd + pidfd `poll(2)`), and hands the proxy one end of a private **socketpair** as `--fd=3`. Two hard parts. (a) The fd must reach the child **without** CLOEXEC — `execve(2)` *closes* CLOEXEC descriptors (the inverse of the usual "protect the fd" reflex): `pre_exec` dups the end onto 3, *clears* the flag, closes the original (exactly one reference — a second fd for the same end keeps the peer alive). The proxy writes one `x` byte on startup (the sidecar's readiness gate) and exits when its fd sees the peer close (`g_io_add_watch(G_IO_ERR\|G_IO_HUP)`) — so even a SIGKILL'd sidecar tears the proxy down. Socketpair, not pipe: with the installed GLib 2.90 that watch does **not** fire on pipe EOF, but does on a socket peer close (the same thing flatpak passes). (b) GLib 2.90 masks `G_IO_ERR\|G_IO_HUP\|G_IO_NVAL` out of the events it hands `ppoll(2)` (an IRIX-era workaround — see `g_main_context_query_unlocked`), so the watch is polled with *zero* requested events and fires only because the kernel reports `POLLHUP` in `revents` even when unrequested — verified with an `LD_PRELOAD` ppoll tracer dumping the array. The child also resets its signal mask in `pre_exec`: a proxy orphaned with every signal blocked would be killable only by SIGKILL. The long bug of Phase 7.2: a socketpair rewrite dropped `--fd=3` from the *argv* — the proxy (told nothing) never wrote the sync byte, the sidecar parked forever in its readiness `read`, and the child outlived the sidecar; nothing about the GLib/kernel path was wrong. The gdb ppoll-array dump (fd 3 absent) vs a shimmed control run (fd 3 present, `events=0`) exposed it. |
| 37 | Xwayland runs *host-side*, not inside the sandbox; the satellite owns a bound socket and a chosen display number | `apse xwayland` (7.3) gives a sandboxed app an X server by running Xwayland on the host as an ordinary Wayland *client* of the desktop compositor, sharing only its X socket into the sandbox through the per-instance runtime dir. The in-sandbox alternative (Xwayland inside the ns, connected to the tagged socket) was rejected on two counts: (a) the X server is the least-trusted component of the X stack — it can read every client's pixels and inject input — and running it inside the sandbox would hand *that* component the app's full capability set (network, home rw); a host-side satellite is the same documented trust tier as the dbus sidecar and the relay, not a new hole; (b) the private rootfs would need the entire X/GL stack (Xwayland + glamor/EGL/driver + libraries) — a large, version-sensitive surface for a rarely-used feature. Mechanically the satellite mirrors the `dbus-proxy` sidecar, and Xwayland's spawn mirrors sway's own (verified on this machine: `Xwayland :0 -rootless -listenfd N -listenfd M -displayfd K -wm W`): the sidecar creates and binds the socket itself (`-listenfd`, non-CLOEXEC — the #36 fd contract), uses `-displayfd` as the readiness gate (Xwayland writes the display number in use when it can take clients; a mismatch against the requested `--display` is a hard error — Xwayland will not silently renumber, and the app's profile must name a stable display), runs `-rootless` by default (the window integrates with the desktop) and passes `-nolisten tcp` (never a TCP listener). The originally-planned `-once` flag proved to be XDMCP *session* semantics (terminate on XDMCP retransmission timeout) — a no-op for a non-XDMCP rootless Xwayland, which does **not** exit when its last X client disconnects — so it was dropped. The lifetime backstop for a SIGKILL'd satellite is instead `PR_SET_PDEATHSIG`, set in `pre_exec` and *re-armed inside the child* by a small `LD_PRELOAD` restore shim compiled on demand into the instance dir: on this machine the exec is a SELinux domain transition into `xserver_t`, which changes the process's security credentials, and the kernel clears pdeathsig on any exec that does (`security_bprm_committing_creds`) — with **neither** setuid **nor** `AT_SECURE` (both stay unset, which is why glibc still honors `LD_PRELOAD` there; the re-set is a harmless no-op on systems that do not clear it). The instance socket is the *only* host-visible X path: given `-listenfd`, Xwayland does **not** create the conventional `/tmp/.X11-unix/X<N>` (a live `X0` on this host was a stale leftover of a dead instance, not sway's bind). And the sidecar must `listen(2)` the socket it creates before the handoff: Xwayland's `-listenfd` path (libXtrans `SocketReopen`) adopts the fd *as-is* and never calls `listen` itself — a socket handed over unlistened makes the server's `accept(2)` fail `EINVAL` on every poll wake, a 100%-CPU hot spin (sway's spawn, which listens first, is the model). |
| 39 | devpts must not be mounted `MS_NODEV` | The sandbox's `/dev/pts` is a newinstance devpts, mounted with the conventional fresh-`/dev` flag set `MS_NOSUID\|MS_NODEV`. The VFS `may_open_dev` (`fs/namei.c`) denies `open(2)` of **device files underneath an `MNT_NODEV` mount** (or a superblock with `SB_I_NODEV`) — an EACCES decided in the open-path permission check, *before* any LSM hook, and *never* audit-logged. Effect: the app could never open `/dev/pts/ptmx` (or any allocated pty slave) — every pty consumer in the sandbox failed at the first `open(2)` with EACCES regardless of DAC (0666), Landlock, or SELinux. It is a pure VFS gate on *device* files only, so it masquerades as a MAC problem (the pts *directory* opens fine, regular files on adjacent mounts open fine). Diagnosis trap (post-mortem): the symptom mimics a Landlock/SELinux denial closely enough that an entire investigation went into the Landlock walk and the genfs labels; the discriminators are a flags A/B on one mount (NODEV on/off) and the absence of any `avc`. Fix: devpts mounts `MS_NOSUID` only (`src/sandbox/mounts.rs`); the fresh `/proc` keeps NOSUID/NODEV/NOEXEC (no device files under proc). |
| 40 | The `run` teardown must not destroy a sidecar socket sharing the instance dir | The per-instance runtime dir (decision #28) is **shared**: the `--proxy` relay, the `dbus-proxy` sidecar, and the `xwayland` satellite all bind their public socket there, and a sidecar's listener outlives every `run` that shares the instance. The historical teardown was a blind `remove_dir_all` on every exit: the sidecar's listener fd survives the unlink, but its path is gone — the next `run`'s carry hands the sandbox an *empty* dir and the app finds no compositor ("no compositor running?"); the sidecar only appears to work while no `run` has since terminated. The fix is both halves of the lifecycle. (a) **Teardown** — `remove_runtime_dir`/`sweep_runtime_dir` (`src/sandbox/mod.rs`): the dir is swept level by level; each **socket** is liveness-probed with `connect(2)` (the same test `bind_socket` uses when it refuses to steal a live socket) and kept while served (the probe connection is dropped immediately — the relay sees one instantly-closed connection), stale ones (connection refused) are removed exactly as before, **its own** tagged socket is unlinked by path without probing (it is served by the compositor's dup, not by this process, and the now-dying dup could still accept a probe — the untag already happened with the listener drop), the app's per-run state is removed as before, and the dir is `rmdir`'d only when nothing live is left: the cleanup is **lazy** — the dir survives while a live socket is in it and the first teardown with nothing live removes it, so the sidecar never has to clean up after itself. (b) **Sidecar (re)start** — `bind_socket` (`src/wayland/listener.rs`): `bind(2)` needs the parent dir, and the last `run`'s teardown may have removed it, so the bind recreates the parent first (owner-only 0700, tightened only when *we* just created it — a pre-existing dir keeps its mode, so an ad-hoc `--listen /tmp/x` must not re-mode `/tmp`). This also fixes the SIGHUP in-place re-exec (the re-exec re-runs `bind_listener` after a run has torn the dir down). All teardown steps are best-effort: a failure loses only hygiene, never the run's result. Verified e2e (v2.14): a relay bound before a `run` survives the run's teardown, and the next `run` reaches the compositor through it. |
| 41 | A run must not orphan the app's namespace when the pipeline dies mid-run | **Run #1**: S died silently mid-run (the cause was never identified — no core, no journal event, no error line), A died shortly after, and the app's pidns (B is its PID 1 — #13: immune to default-action signals from outside the namespace) ran on forever; the only trace was the sub-cgroup `rmdir` failing `ENOTEMPTY`. Two code-level holes can produce that cascade, and both are now closed (`src/sandbox/mod.rs`, v2.15, LESSONS #37). (a) **`EINTR` was fatal in both reapers' blocking `waitpid`s** — S's through `?` (the error exits the whole run), A's through a 126 exit. Both reapers live to block in `waitpid` and block *exactly* the three signals they forward (the signalfd is their sole consumer), so every other signal is at its default disposition and reaches them *delivered* — a terminal session's SIGTSTP/TTIN/TTOU, a SIGCHLD, a segfault — and a delivered signal interrupts the blocking `wait4`; the old code treated the resulting `EINTR` as fatal in both places. A dead A reaps nothing (B reparents to the host init); a dead S takes the forwarder thread — and with it the 2 s KILL escalation, the only thing keeping B finite. `waitpid_retry` loops on `EINTR` in both. (On 7.2.11 the empirically reachable set is narrow — a STOP→CONT cycle restarts the wait, a manually sent SIGCHLD is consumed by the wait itself — but a reaper that must live must never die on an interrupt; the fix is by principle, not by enumerating interrupts.) (b) **There was no backstop for any other S exit with the app alive** — an error `?`, a panic, a dead A reaped by S. The `AppKillGuard` is armed the moment the handoff completes and dropped at the end of the run; its `Drop` reads the instance sub-cgroup's `cgroup.procs` — recursive on cgroup2, and since A moved in before the unshare (#20) and B entered with it, the list is A + B + every descendant — and SIGKILLs whatever is still alive. It does *not* rely on the kernel's zap of a dying pidns init (#14: on 7.2.11 strays reparent and survive). On the normal path the sweep is an empty no-op; it fires — loudly, with a warning — only when a live process is found, i.e. exactly the incident. **Field-verified** by SIGKILL-ing A (the run-#1 cascade with an identified trigger): the old code reproduced the orphan (S exited 137; B+child immortal; `rmdir` `ENOTEMPTY`), the new code left no process (the guard fired on 2). **Remaining boundary:** a *default-terminate* signal **to S itself** (SIGKILL, a segfault, SIGQUIT, …) kills the guard with it — `Drop` runs only on unwinding exits (an error `?`, a panic), not on a fatal-signal death — and A and B survive; that is the actual run-#1 shape, and it needs the kernel-level `PR_SET_PDEATHSIG` cascade: A←S (A never execs, so a `pre_exec` set survives) and B←A (B execs into `apse_app_t`, a security-credential change — the kernel clears pdeathsig on such an exec (`security_bprm_committing_creds`) — so B needs the decision-#37 `LD_PRELOAD` restore shim). Now implemented (decision #42) and field-verified on both legs (LESSONS #44). |
| 42 | A S-death the `AppKillGuard` cannot intercept (a default-terminate signal to S itself) must still end the app (the run-#1 boundary left by #41) | The guard dies with S, so this needs a kernel-level `PR_SET_PDEATHSIG` cascade where each process's death propagates to the process it supervises (`src/pdeathsig.rs` new; `src/sandbox/mod.rs`; `src/xwayland.rs`; v2.16). **A←S**: A sets `pdeathsig = SIGUSR1` right after its first fork (before the unshare). Deliberately `SIGUSR1`, not `SIGTERM`: A keeps the pre-fork TERM/INT/HUP block (it must survive a group-wide Ctrl-C until it reaps B), and a pdeathsig that lands in a block stays *pending* forever and never fires, while the block must stay. Nothing else in the pipeline sends USR1, so the signal means exactly "S is gone". A never execs, so the setting survives. The handler is installed *after* the second fork so B does not inherit it (B's USR1 stays at its default kill disposition — the pre-exec answer to "A is gone"); it only stores an `AtomicI32` flag (a single-word store is the whole of its async-signal-safe work). The delivery `EINTR`s A's blocking `waitpid`; `waitpid_retry` (gained an `interrupted` flag) reports that `EINTR` *unwrapped*, and A tears down in normal context: kill B with `SIGKILL`, exit 137. **B←A**: 7.2 `fork` *resets* `pdeath_signal` to 0 (`kernel/fork.c` — not inherited), so B re-arms `SIGUSR1` itself right before its own exec; in confined mode the exec changes the process's SID, and `selinux_bprm_committing_creds` (`security/selinux/hooks.c:2545`, commit `4ac212ad4e8f`) unconditionally zeros `pdeath_signal` on any SID change — so an `LD_PRELOAD` shim (`ensure_shim`'s constructor calls `prctl(PR_SET_PDEATHSIG, SIGUSR1)`) re-arms it after the exec. `prctl` is not trapped by the seccomp-notify filter, and the loader's `openat` is trapped but allowed (the file sits in the app's own writable runtime dir); in confined mode `ensure_shim` additionally relabels the `.so` to the module's dedicated `apse_shim_t` type — a 7.2 `PROT_EXEC` mapping needs `file:execute` (`file_map_prot_to_av`), which the confined consumer types hold only on that type (LESSONS #41). The on-demand compile itself runs under a *pinned* exec context (S writes its own current context to `/proc/self/attr/exec` before vforking `cc` and clears it after — a vforked child shares S's cred, so the module's `typetransition` would otherwise drag the compiler into `apse_app_t` on its exec; LESSONS #42). In unconfined mode no shim is built (nothing clears the belt). **7.2.11 semantics (verified against `~/src/linux`)**: `fork` resets the value unconditionally (`kernel/fork.c`); `execve` has three clearing paths — `bprm->secureexec` (setuid/setgid/a capability gain, or a *denied* `noatsecure` SELinux check, `security/selinux/hooks.c:2468` — `fs/exec.c` clears the belt on it), an actual uid/gid/caps change (`commit_creds`, `kernel/cred.c:390`), and — the one that decides here — the **unconditional** zero on *any* SID change in `selinux_bprm_committing_creds` (`security/selinux/hooks.c:2545`, commit `4ac212ad4e8f`); the earlier assumption that the confined exec's clear went through `secureexec` (a *denied* `noatsecure`) was wrong in both directions — the clear is unconditional, and this policy *grants* `noatsecure` on the `apse_t` → `apse_app_t` transition, so that path does not even fire on the app's exec (it does on the `xserver_t` transition, where it is not granted; `commit_creds` does not fire at all — same uid, no capability gain). A *same-domain* exec (unconfined) changes no SID and sets none of the clearing conditions, so the belt survives — which is why the shim is built only in confined mode (it was also field-verified necessary on the decision-#37-era kernel, LESSONS #19–20); `PR_GET_PDEATHSIG` writes the value to the pointer in `arg2` and returns 0/-EFAULT (`kernel/sys.c`) — the ≤ 6.x convention of returning the value is gone. The same module serves the `xwayland` satellite (`SIGTERM`); the shim file is signal-suffixed (`pdeathsig-restore-<sig>.so`) so the two signals do not collide in the shared per-instance runtime dir. **Tests**: three new unit tests (set/get + the fork reset; a plain same-uid exec preserves the belt; the shim re-arms after exec), plus `a_tear_down_on_s_death_flag` (a one-shot timer delivers USR1, the `waitpid_retry` escape fires, B is killed, exit 137). **Field-verified on both legs (2026-11-03, v2.17, LESSONS #44):** SIGKILL S → the belt's USR1, A's handler tears B down; SIGKILL A → the belt's USR1 observed in B (the strace signature `si_code=SI_USER`, `si_pid=0` — the cross-pidns pdeathsig marker; a kernel-internal delivery invisible to the audit exit filter), the `AppKillGuard` sweep ends the run, no orphans. The one piece not cleanly isolated: B's own USR1-terminate disposition (B resumed via `restart_syscall` — an `SA_RESTART` action is suspected from the Rust ELF/dynamic-linker startup — and died on the guard's KILL, not the belt's); it is not load-bearing while the guard exists. |
| 43 | The app's `$HOME` and XDG dirs: the real home, or a private per-app state? | **Default: a private per-app state tree** (2026-11-11; the container-era per-app home volume, re-implemented for the in-process world — the quadlet units gave each app a podman home volume plus per-app XDG volumes, persistent and disconnected from the host desktop). The profile gains a `home` mode; the default (ad-hoc and built-in) is `"private"`: S creates, before the first fork, a **per-app (not per-instance)** tree at `$XDG_STATE_HOME/apse/<app-id>/` (home/config/cache/data/state subdirs, all 0700; the default state dir makes it `$HOME/.local/state/apse/<app-id>/`) and never removes it — it *is* the app's persistent state. The rootfs build (step 7) binds its subdirs over `$HOME` and the XDG locations. Order and traps: the tree is carried into the step-1 scratch *before* the real home is replaced (its host path sits under the home step 7 replaces — a source resolved after that bind would hit the private copy; the runtime-dir carry's trap, #28); the binds go home → config → cache → data → **state last** (a state dir may nest under the data dir, and each target must resolve after the binds beneath it); targets under the home are pre-created by S (the bind is unconditional), a custom XDG outside the home is bound only when it exists. The app's environment keeps its historical XDG strings — the redirect is invisible; the in-sandbox path simply resolves to the private tree. **CWD:** in private mode, B `chdir`s to the app's home before the exec — the inherited CWD is the host's launch dir, which sits under the real home and disappears when it is replaced, and an app that forks and `chdir(cwd)`s before its exec (foot's `slave_spawn`) dies on the bad chdir before reaching the exec; host mode keeps the inherited CWD (a real, existing path). Policy: one ReadWrite grant per existing home/XDG target (the same target strings in S and B — Landlock resolves through the binds to the state-tree inodes), and the mode is validated before the fork. `home = "host"` keeps the pre-8.3 behaviour (real dirs rw self-bound); the profile's `rw_binds` layer on top in both modes. **Confined mode:** the tree is the module's dedicated `apse_state_t` (refined 2026-11-12, v2.21): the `apse` root that `apse_t` creates under `~/.local/state` (`gconf_home_t`) is *born* `apse_state_t` via a named filetrans — spelled in this module store's CIL dialect as the five-field `typetransition` (there is no `filetrans` keyword), since on this kernel `filecon` does not label created inodes — and the no-rule default (the parent's own type) makes the whole subtree inherit it; S's setxattr walk (`prepare_app_state` → `relabel_state_tree`) performs the one-time migration of a pre-module (gconf-labelled) tree and self-heals stragglers. S gains the dir create/setattr/`mounton`/relabel grants; the app gains the full file lifecycle on the tree (incl. fish's `lock`/`watch`) plus `entrypoint`/`execute`/`execute_no_trans` on `apse_state_t` files (B's exec-context exec of a file out of the private home, and its own children) and the `apse_t → apse_app_t` fallback transition plus new-process attributes; `unconfined_t` gains the user's inspection lifecycle (and the test-suite pipeline, which runs unrelabeled). The `gconf_home_t` grants remain for the *parent* `~/.local/state` dir and for the real home in host mode. Field-verified (2026-11-12): `ps ax` run directly through `apse run` in the confined sandbox (the same `apse_app_t` domain and pidns as a shell inside foot) with zero denials — its fixes needed `open` (opendir) on top of `read` (getdents) for the `proc_t`/`sysfs_t`/`sysctl_kernel_t` dirs, a self-referential `dir:ioctl` for ps's tty probe on its own `/proc/<pid>` dir (MCS-bounded in effect), and `bin_t:dir open` for fish's completion enumeration. **Tests:** the rootfs reference test asserts a `$HOME` write lands in the per-app state tree and never the real home; the integration suite adds a hermeticity marker (a real-home file must not be visible through the private `$HOME`) and a private-home write to the Landlock probe. |

## 7. Phases & task list

> Each phase ends with a working, committed state. "Verify" items run on
> the target machine (Fedora 45, sway, unprivileged user).

### Phase 0 — Cleanup & skeleton
- [x] 0.1 Delete `containers/` (`0c842cf`)
- [x] 0.2 Delete `docker-bake.hcl`, `systemd/`, `selinux/`; `Dockerfile` deleted (`42191e9`)
- [x] 0.3 Restructure `src/` into a binary crate with modules:
      `cli.rs`, `wayland/{mod,listener,context,signals}.rs` (move current
      code + all its tests, no behaviour change), `sandbox/`, `profile/`
      (the `wayland` modules have since been reorganised: `signals.rs`
      is gone, `roundtrip.rs` added)
- [x] 0.4 Add deps: `nono` (pinned at 0.80.0, default-features off to
      drop `keyring`), `toml`, `serde`

### Phase 1 — User namespace, non-root mapping
- [x] 1.1 `sandbox/userns.rs`: fork + `CLONE_NEWUSER`; `setgroups=deny`;
      **single write** of `uid_map`/`gid_map` — one extent each,
      `<self> <self> 1` (decision #10; the old two-entry form is
      EINVAL on modern kernels)
- [x] 1.2 Credential verification (`verify_locked`): ruid/euid/suid =
      the real uid; CapEff is the full ns set (nothing is dropped —
      the map locks the identity); `setresuid(0)`/`setresgid(0)` are
      EINVAL (decision #10)
- [x] 1.3 `apse run -- <cmd>` ad-hoc path to observe results (CLI
      becomes a subcommand tree: `run`, `wayland`)
- [x] 1.4 Verified on this machine (Fedora 45, kernel 7.2.11-300.fc45,
      from the dev container's level-2 user ns — the *stricter* case;
      the plain level-1 session on the same kernel is a subset of the
      permission checks): `id` inside shows the real uid; the
      write-once probe passes (second write EPERM, map unchanged); the
      full ns cap set is held at exec; a rejected map is a hard test
      fail, not a skip
### Phase 2 — Remaining namespaces
- [x] 2.1 Mount ns (unshare right after user ns; rootfs build lands in
      Phase 3 but the unshare slot is here)
- [x] 2.2 PID ns: extra fork so the app is PID 1; death semantics
      (kill app → whole ns gone) — see #14 for the real teardown story
- [x] 2.3 IPC ns + UTS ns (hostname `apse-<app>-<instance>`)
- [x] 2.4 Cgroup ns: enter the `app` sub-cgroup **before**
      `unshare(CLONE_NEWCGROUP)` (the original unshare-then-move order
      rooted the ns at the session cgroup and is corrected — #20);
      verify `/proc/self/cgroup` view — #12 for the 7.2 dance
- [x] 2.5 Network ns per mode (`none` = bare netns + `lo up`)
- [x] 2.6 Verify full set against a reference
      (`the_full_ns_set_is_fresh`: all 7 ns kinds fresh, `/proc/self/ns`
      names incl. the 7.2 quirks of #16)

### Phase 3 — Rootfs
- [x] 3.1 `sandbox/mounts.rs`: the §3.3 table as code: `/dev` tmpfs +
      node bind-mounts + `devpts -o newinstance`; fresh `/proc`; `/sys`
      ro-binds; `/run`+`/tmp` tmpfs; ro/rw binds; masks; `chroot`
- [x] 3.2 `profile/`: TOML app profiles; defaults for rustrover/librewolf
- [x] 3.3 `/dev/dri` bind + GPU check (render group), `--no-gpu`
- [x] 3.4 Verify: mount table matches the reference; `ls /` minimal;
      host Wayland socket absent; `/dev` nodes openable by the app

### Phase 4 — nono: landlock + seccomp

**Design** (verified against the nono 0.80.0 source, 2026-10-22):
- **B, pre-exec (three-stage apply, #27):** (1) *prepare* the Landlock
  policy (`prepare_landlock_with_abi`) — it opens every rule path, so
  it must run before the filter exists (a filter installed first would
  trap its own `open(O_PATH)`s → deadlock).
  (2) install the *combined* seccomp-notify filter —
  `prepare_seccomp_af_unix_filter().with_openat_notifications()`; Linux
  allows one `NEW_LISTENER` filter per thread, so the AF_UNIX mediation
  (traps `connect`/`bind`/`sendto`/`sendmsg`/`sendmmsg`) and the openat
  logging (traps `openat`/`openat2`) share one listener (#22).
  (3) *apply* the Landlock floor (`apply_raw`) — default-deny fs,
  signal scoping (V6), `no_new_privs` (locks the single-extent
  identity, #10); it uses the prepared fds, no new opens.
  (4) hand the notify-fd *number* to A over a pre-made B→A pipe
  (#23). (5) block on A's *verdict* over a pre-made A→B pipe —
  `1` = the listener is in S's hands, exec now; `0` = the handoff
  failed, exit 126, never an unsupervised exec (#26). The wait is
  mandatory: the listener is `O_CLOEXEC` in B's table (the kernel
  allocates it that way) and `pidfd_getfd` on B succeeds only while B
  is the still-dumpable *pre-exec* process.
- **A:** reads the number, extracts its own listener fd from B's fd
  table via `pidfd_open`+`pidfd_getfd` (A is B's parent, same uid —
  ptrace-permitted; the pid resolves *globally*, so the host pid
  returned by `fork()` is the right argument even from inside A's
  pidns — #29), sends it to S via `SCM_RIGHTS` over a pre-made S↔A
  socketpair, then sends B the verdict (#26). Close ordering: A drops
  its copy of the verdict read end only *after* the second fork (B
  must inherit it), and ignores `SIGPIPE` after the fork — a
  failure-path verdict can hit a pipe whose reader (B) is already
  gone, and that must not kill A before it reaps B and propagates B's
  status. Direct SCM_RIGHTS from B is impossible: its `sendmsg` is
  already trapped (#23). If the handoff fails (B died early) S falls
  back to a plain `waitpid` — landlock still applies.
- **S (the supervisor):** a `poll(2)` loop directly over the
  seccomp-notify listener fd (handed off per #23 — there is no separate
  supervisor socket: the notify fd is the only seccomp channel, #22).
  Dispatch by syscall number: openat → resolve the path from `/proc/<pid>/mem`
  (`read_notif_path`/`resolve_notif_path`, `read_open_how` for
  openat2), check the capability allowlist → continue or
  EACCES+log; socket syscalls → read the sockaddr, *pathname* AF_UNIX
  must match a granted socket (abstract/unnamed denied — #25),
  non-UNIX families pass through (shared netns is the network
  default). The supervisor never *expands* access in this phase
  (no fd injection); landlock remains the floor. Loop ends when A dies
  (B's death tears down the whole pidns, #14).
- **CapabilitySet** (`policy.rs`): base "app essentials" — `/` Read
  (refer/traverse — required, nono grants no ancestor metadata on
  Linux, #24), `/usr /lib /lib64 /bin /sbin /etc /proc /sys` Read,
  `/dev` RW, `/tmp` RW, the per-instance `/run` dir RW, the app's
  home and XDG dirs RW — one ReadWrite grant per existing home/XDG
  target (decision #43: the private per-app tree by default; the real
  dirs with `home = "host"`);
  plus profile `ro_binds`→Read, `rw_binds`→ReadWrite, `mask`→no
  grant, `unix_sockets`→`allow_unix_socket`, the instance-dir subtree
  (home of the Phase-5 tagged wayland socket), network
  shared→AllowAll / none→Blocked, `signals`/`ipc` per profile.
  Built identically in S and B from the same pure function (B inherits
  nothing but re-runs it).
- **4.1–4.4 checklist**
- [x] 4.1 Build `CapabilitySet` from profile: fs paths + modes, unix
      socket caps (tagged wayland, later dbus/ssh), network mode, signal /
      process-info / ipc modes (`policy.rs`; the same pure function runs
      in S and B)
- [x] 4.2 Apply after the credential sequence, before `execve` in the
      child; the install path is nono's three-stage
      `prepare_landlock_with_abi` → install combined filter →
      `apply_raw`, plus the notify-fd handoff to the supervisor
      (#23, #26, #27)
- [x] 4.3 Supervisor side: hold the seccomp-notify fd (received by
      `SCM_RIGHTS` from A), a poll loop that mediates
      openat/openat2 (against the same `CapabilitySet` that built the
      floor) and the AF_UNIX socket syscalls (granted pathname sockets
      allowed, abstract/unnamed denied — #25), auto-deny with
      `EACCES`, denials logged; exits when the notification queue
      drains (the app died) or on the stop flag
- [x] 4.4 Verify (the four Phase-4 tests in `supervise::tests`):
      openat write outside every granted subtree → `EACCES` while the
      write into the granted instance subtree crosses the bind to the
      host; read of a base-granted path returns the host file
      verbatim; `connect` to an ungranted AF_UNIX socket → `EACCES`;
      `connect` to a socket in the instance subtree is mediated
      *allow* — the payload reaches the host-side listener. Network-per-
      mode and "a normal GUI app runs" remain with 5.5 (strace-driven
      tuning of the filter, if needed, happens there).

### Phase 5 — Wayland + full pipeline
- [x] 5.1 Tagged-socket creation moves ahead of the fork (supervisor
      side, reusing the existing listener/roundtrip/context code)
- [x] 5.2 Reference pipe handed to the app (socket lives while the app
      lives; app death invalidates it — clean lifecycle)
- [x] 5.3 `apse run <app-id>`: profile → env → `execve`
- [x] 5.4 sd-notify (READY on child spawn), signal forwarding
      (TERM/INT to app; keep SIGHUP→129 semantics), exit-status
      propagation, `/run` dir cleanup
- [x] 5.5 E2E on target: a real GUI app runs through the full S→A→B
      pipeline on this desktop — done with **Firefox** (2026-10-24,
      `--no-gpu`, profile `~/.config/apse/apps/firefox.toml`): the
      window reached the compositor (`org.mozilla.firefox` in sway's
      tree), network egress worked (neqo/Glean uploads in the log), and
      the supervisor forwarded SIGTERM and reaped the app cleanly
      (exit 15). The in-sandbox identity probe (same pipeline, ad-hoc
      `sh`) verified real uid 1000, hostname `apse-probe-1`, `0::/`
      cgroup view, the app as PID 1, and the rebuilt rootfs with the
      expected masks.

**Phase 5 decisions.**
- **30 — In-sandbox path grants.** The `CapabilitySet` and the app's env are
      built from the *in-sandbox* path (`/run/user/<uid>/apse/<inst>`,
      decision #28's carry), not the host path: the app presents sandbox-side
      strings to its trapped syscalls, so the grants must match those strings.
      The wayland socket is granted by its tagged path. CLI: `run` gains
      `--wayland/--listen/--socket-activation/--sandbox-engine`.
- **31 — `open` ≠ `connect` on a unix socket.** `open(2)` on a unix socket
      returns `ENXIO` (bash `exec 3<>` does `open`); the app must `connect(2)`.
- **32 — The supervisor services every trapped notification (original
      per-pid arming resolved, 2026-10-24).** Originally the supervisor
      armed B's pid only, and a *child* of the pidns-init app issuing a
      trapped syscall was never serviced → handoff deadlock (observed: the
      openat-write test hung with the subshell stuck in
      `unix_stream_data_wait`). The supervisor now services *every*
      notification on the listener — `handle_notif` dispatches by syscall
      number with no pid filter, and a failed verdict answers EPERM rather
      than hanging — so children that inherit the seccomp filter are served
      with the same capability set. The Firefox e2e (5.5) confirms a real
      multi-process GUI app (browser + gecko/socket children) runs and exits
      cleanly; the remaining caveat is app-internal pipe behaviour, not a
      supervisor gap.
- **33 — Signal forwarding & shutdown.** S blocks `SIGTERM/SIGINT/SIGHUP`
      before spawning any thread (all threads inherit the block). A forwarder
      reads them from a `signalfd`: TERM/INT → `kill(SIGTERM)` to the app then
      `SIGKILL` after a 2 s grace (decision #13 — pidns-init ignores
      default-action signals); HUP → same, exit status 129. The app's host pid
      is reported A→S over the S↔A socketpair (A is in the parent pidns). After
      the handoff S sends `READY=1` (no-op without `$NOTIFY_SOCKET`). Teardown
      joins both threads, drops the tagged socket (untag), and `remove_dir_all`s
      the per-instance runtime dir (still at its host path — the step-1 carry is
      a bind).

### Phase 6 — systemd integration (revised #35: D-Bus primary)
- [x] 6.1 D-Bus session-bus `StartTransientUnit` scope via `zbus`
      driven on a **fresh local tokio runtime per call** — never
      `zbus::blocking` (v5), whose wrapper hides a *process-global*
      `OnceLock` runtime that is dead in a `fork(2)`-ed child
      (worker threads don't survive the fork; `block_on` on it hangs
      — the test harness forks this path, so the parallel suite
      deadlocked until the call was made runtime-local; the async
      API is the same one 6.0.0 is built on, so the later migration
      is small): `PIDs=[self]` only (no StopWhenUnneeded/Delegate).
      On `UnitExists` the unit is **adopted, not blindly stopped** —
      `StopUnit` on a scope *kills its members* (`scope_enter_dead` →
      `unit_kill_context`, v261 source): already a member → keep;
      empty (`Tasks==0`) → stop, refresh `PIDs`, start; busy (foreign
      tasks) → never touched, the run degrades. The call is async
      (the job is only queued): a ≤3 s poll of `/proc/self/cgroup`
      confirms the move. After the call A's pre-unshare cgroup
      capture lands the instance sub-cgroup inside the scope (no A/B
      change); tier logged. The local runtime's worker threads are
      spawned from the calling thread and inherit its mask, so the
      forwardable-signal block (5.4) stays *ahead of the call*: the
      forwarder stays the sole consumer; A unblocks again before
      forking B, so the app keeps its historical (unblocked) signal
      behavior. Unit
      test: with a session bus — attach self, assert moved + child
      accepts a pid + recursive removal; without — assert raw tier
      (never a silent skip)
- [x] 6.2 Raw-cgroup fallback (no session bus / no user systemd /
      call failed): the #12/#20 path; the degradation's user-visible
      semantics are documented on `ScopeTier::Unavailable` (sandbox
      unchanged; only unit visibility/accounting lost; the instance
      sub-cgroup still created under `S`'s current cgroup and
      cleaned up on exit)
- [x] 6.3 `apse wayland` remains usable standalone (per-app proxy /
      socket-activation units are up to the user; the repo ships only
      the broker units, re-homed in 7.1). Verified on this desktop
      2026-10-23: both the tag-and-park and `--proxy` modes run with
      `--listen` with no units at all (the e2e of the merge session);
      the socket-activation path is unit-tested
- [ ] 6.4 *(future, #35)* varlink tier once a released systemd ships a
      scope context with `PIDs` in `io.systemd.Unit.StartTransient`
      (main only as of 2026-10-16, after v262; rechecked 2026-11-04:
      still main-only — v263 is in development, newest release is v262
      of 2026-09-22, and Fedora 45's 262.1 exposes no user-bus varlink
      socket at all, `/run/systemd/user/io.systemd.System`)

### Phase 6.5 — Wayland proxy & prompt broker (clipboard branch, merged `21b26dd`)

The clipboard branch built the `--proxy` relay and the host-side
broker as its own workstream (its phases 1–9, tracked in its own
TASKS.md); the 2026-10-23 merge folded that work in here. All of it
is integration-tested (`tests/proxy_integration.rs`,
`tests/broker_integration.rs`):

- [x] 6.5.1 Mode A relay (`wayland --proxy`): convention-adaptive
      object bookkeeping between the app's connections and fresh
      tagged security-context connections (`src/proxy/`; the fd
      misrouting defect and its fix:
      `docs/postmortems/fd-swap-fix-plan.md`). SIGHUP is a rebuild,
      not a stub: an in-place re-exec of `/proc/self/exe` in
      `--listen` mode (same pid; re-binds and re-tags the freed
      socket) and a clean exit for a systemd restart when
      socket-activated.
- [x] 6.5.2 Global allow-list (`--allow-globals`): filters the
      `wl_registry` globals and rejects binds of non-allowlisted
      interfaces. **Absent flag = pass-through** (`Policy::all()`).
      The branch-era code mapped *absent* to an *active-but-empty*
      allow-list (hides everything) — the desktop e2e caught it;
      fixed in `1e46e3b`.
- [x] 6.5.3 Clipboard receive-gate (`--clipboard-policy=deny`): a
      dropped read becomes a consent request to the broker (allow =
      a 1500 ms intent window; deny and every failure path fail
      closed); clipboard/primary writes are audited, and
      `--notify-copy-out` fires a one-way `clipboard-write`
      notification (fire-and-forget, fail-open, rate-limited to one
      per selection per second per app — the window is anchored on
      the *fired* notification, so a continuous stream never
      starves).
- [x] 6.5.4 Prompt broker (`apse broker` + `apse decide`):
      N-D-JSON over the broker socket; a session decision socket
      (`$XDG_RUNTIME_DIR/apse/decision.sock`, bound once for the
      life of the session, chmod 0600) so several prompts can be
      pending at once — FIFO, `--prompt <id>` targets — and
      `decide` without `--decision` lists them. `notify-send`
      announces with a ready-made reply command; a timeout is a
      deny; a failed decision-socket bind degrades interactive
      prompts to a deny at once (`no-decision-socket`) while copy-out
      notifications keep working; `--auto-decide` never binds the
      socket.
- [x] 6.5.5 Selection audit log (branch phase 9): one `key=value`
      record per `set`/`read`/`clear`/`serve` event to the **host
      journal** (the relay logs to stderr); payload recorded as
      **size only, never content**; no rate-limiting (a persistent
      record, not a digest). Drag-and-drop fully closed (the write
      audit 2026-10-24, v2.13; the `serve`-label drag refinement
      v2.19, 2026-11-04): a `start_drag` is audited as a write
      (`action=set selection=drag`, its own copy-out notification),
      and the relay tracks the client's active drag source (a
      `start_drag` until that source's `cancelled`/`dnd_finished`/
      `destroy`; a `dnd_drop_performed` does *not* end it — a "move"
      drop transfers its data on the drop, so those serves stay the
      drag's) so the `serve` records for bytes served *during* a drag
      are labeled `selection=drag` (the `wl_data_source` is shared by
      the clipboard and the drag and the wire does not say which),
      while the `read` on the stable-protocol offer stays
      `selection=clipboard` — the exact contrast the refinement
      exists to make. Verified end to end (`drag_serve_is_audited_as_drag`)
      and at unit level (`the_active_drag_source_lifecycle`).
- [x] 6.5.6 Protocol-table CI (branch deferred refinement):
      `scripts/gen_interface_table.py` regenerates `interfaces.rs`
      from `protocols/*.xml` and CI diffs the result
      (`git diff --exit-code`); `wlr_tables.rs` is the compiler's
      sync check (the `wayland_scanner::generate_interfaces!` macro
      expands the same XML at build time).
- [x] 6.5.7 Broker arrival order (`9fded8c`): prompts are ordered by
      a sequence stamped in the broker's sequential `poll(2)` accept
      loop, never by the order the per-connection threads happened to
      take the queue lock (LESSONS #17).

**Desktop e2e (this machine, sway; 2026-10-23).** `wayland-info` on
the *tagged* socket sees 35 of the host's 56 globals, and
`wp_security_context_manager_v1` is absent — the nesting guard the
spec requires (a tagged client must not be able to stamp again); on
the host socket the manager is present (name 34). Through the proxy
the same checks hold: after `1e46e3b`, all 35 (before the fix: 0). A
SIGHUP on the proxy re-execs in place (same pid, re-binds and
re-tags, still 35). 5.5 is done (the Firefox e2e, 2026-10-24). The
*full chain* is done (2026-10-24): a sandboxed `wayland-info` is
driven through the `--proxy` relay into the live sway — it enumerates
the compositor's globals and exits 0. The relay's public socket is
bound inside the per-instance runtime dir (the app's in-sandbox
`$XDG_RUNTIME_DIR`), which the rootfs build carries into the sandbox,
so the bare `run` (no `--wayland` tag of its own) resolves
`$WAYLAND_DISPLAY` to the relay. The drag-and-drop audit (6.5.5) is
fully closed: a `start_drag` is audited as a write, and the `serve`
records for bytes served during a drag are labeled `selection=drag`
(the relay tracks the active drag source — see 6.5.5 above).

**Branch TASKS.md follow-ups:** the zbus 5→6 migration is done
(`6725560`); the drag-and-drop audit (6.5.5) is done (`start_drag`
audited as a write).

### Phase 7 — Re-homing the deployment units + sidecars
- [x] 7.1 Re-home the broker deployment for the containerless
      world: `systemd/user/apse-broker.{socket,service}` rewritten
      from the branch-era global-flag forms (`apse --broker
      --socket-activation`, `apse --decide`) to the merged
      subcommand CLI (`apse broker --socket-activation`,
      `apse decide`); verified with `systemd-analyze --user
      verify` and by running the exact ExecStart line. *Decision:*
      per-app proxies stay **documented manual runs**, not a unit —
      the proxy's public socket path must match the app profile's
      env (`XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY`), which is
      per-instance coordination a template instance cannot derive.
      The deployment recipe (incl. the audit sink: the relay's
      stderr → journal via `StandardError=journal` /
      `LogDriver=passthrough` in any unit the user writes) lands
      with the README rewrite in 8.1
- [x] 7.2 `apse dbus-proxy <app> <instance>`: host-side
      `xdg-dbus-proxy` (per-instance; **direct spawn**, not a
      socket-unit — the sidecar *is* the unit-equivalent: it blocks
      its signal mask, owns the child via a signalfd+pidfd `poll(2)`
      loop, and stops the child on SIGTERM/SIGINT/SIGHUP). The
      public socket lands in the per-instance runtime dir
      (`bus.sock`), owner-only from birth (umask 0077 + chmod 0600);
      the app profile's `[env]` points
      `DBUS_SESSION_BUS_ADDRESS=unix:path=…` at it. The sidecar's
      `--see/--talk/--own/--call/--broadcast` map 1:1 to the proxy's
      (with `--filter` implied by the first rule — fail-closed once
      any rule is present). Lifetime is by fd: one end of a private
      socketpair is handed to the proxy as `--fd=3` (non-CLOEXEC —
      `execve(2)` *closes* CLOEXEC descriptors), the proxy writes
      its sync byte there and exits on peer close (decision #36).
      Verified: pass-through `busctl --list`, SIGTERM teardown, and
      SIGKILL-teardown of the sidecar (the proxy dies on the HUP).
- [x] 7.3 (optional) `apse xwayland` host-side satellite
      (design: decision #37). Per-instance `Xwayland` for sandboxed
      X clients: a *host* process (the in-sandbox alternative is
      rejected — see #37) mirroring the `dbus-proxy` sidecar's shape:
      direct spawn, signalfd + pidfd `poll(2)` ownership,
      TERM→2 s→KILL teardown, exit with the child's status. The
      sidecar creates the X socket itself (unix stream, bound to
      `<instance-dir>/xwayland.sock`, owner-only from birth) and
      hands it to Xwayland as `-listenfd` — the same pattern sway
      uses to spawn its own Xwayland (verified on this machine:
      `Xwayland :0 -rootless … -listenfd N -displayfd K`) — with the
      fd made *non*-CLOEXEC (the decision-#36 fd contract: `execve`
      closes CLOEXEC descriptors). Readiness is Xwayland's own
      `-displayfd` (a private socketpair): Xwayland writes the
      display number in use when it can take clients; the sidecar
      cross-checks it against `--display` (default 97, kept clear of
      sway's auto-Xwayland) and fails loudly on mismatch — the
      profile's env must name a stable display, so a silent
      renumbering is worse than an error. `-auth <instance-dir>/
      xwayland-auth` gives Xwayland a cookie file (the app points
      `XAUTHORITY` at the in-sandbox copy, decision #28's path);
      `-nolisten tcp` (never a TCP listener); **no `-once`** (it
      turned out to be XDMCP *session* semantics — a no-op for a
      non-XDMCP rootless Xwayland, which does **not** exit when its
      last X client disconnects, #37; the lifetime backstop is
      instead the decision-#42 `PR_SET_PDEATHSIG` belt, which tears
      Xwayland down whenever the satellite dies); `-rootless` by
      default (the window integrates with the desktop;
      `--no-rootless` for the framed window). The sidecar prints
      the profile env line: `DISPLAY=unix:<in-sandbox socket>`,
      `XAUTHORITY=<in-sandbox auth>`. The instance socket is the
      *only* host-visible X path: given `-listenfd`, Xwayland does
      **not** create the conventional `/tmp/.X11-unix/X<N>` (verified
      on this box — a live `X0` there was a stale leftover of a dead
      instance, #37).

### Phase 8 — Docs, SELinux, hardening
- [x] 8.1 Rewrite `README.md`: architecture, threat model (what changed
      vs. containers; residual risks: network, GPU, downloads, portal
      attribution), install, verify-your-setup, adding an app.
      Done: full container-era replacement — the S→A→B pipeline, the
      rebuilt rootfs and the nono policy, the tagged socket's three
      modes, the relay (allowlist / gate / notify / audit), the
      broker/decider, a 10-layer containment table, install, TOML
      profiles, the per-app relay manual-run recipe (public socket
      inside the instance dir, tagged socket outside it; the app's
      `[env]` routes it through, `run` without `--wayland`), the
      audit-sink journal wiring (7.1's deferred deployment recipe),
      verify-your-setup (56 vs 35 globals, nesting guard), and the
      residual-risk list (network egress, copy-out, GPU, own-home
      exposure, portal attribution, multi-process deadlock, FOOT/PTY
      `EACCES`).
- [x] 8.2 New SELinux policy (2026-10-28: first-pass module built — `apse_t` + `apse_app_t` + the xserver_t fix; reworked from the permissive probe's AVC inventory (tmp_t, the dbus-broker session-bus types, `system:start`, `mounton`-on-file, `dyntransition`); the per-instance MCS mechanics are wired (`src/mcs.rs`: the self-narrowing re-exec in the supervisor/proxy/satellites, the `apse_app_t`/`xserver_t` setexecfilecon carry-overs, the range-preserving re-exec); installed 2026-10-29 as pure CIL (MCS narrowing verified, `cN` live). The enforcing-mode tuning loop is done (2026-10-29): audit2allow against a confined run, ported to the CIL and reinstalled, iterated until a confined `run` (echo+cat+ls) produced **zero denials across nine consecutive runs** (the broker narrows to single-level `s0` in the same pass). The additions landed in two groups — the *runtime* side (the unconfined user's signal/ptrace on apse processes, the SIGHUP-rebuild self-exec `execute_no_trans`, the `listen` on one's own sockets, `dac_override` for B's new-userns mount path lookups, `init_t`'s cgroup bookkeeping) and the *app* side (the `tmp_t` mount root, the `ld_so_t` loader `open`, the `locale_t`/`passwd_file_t` lookups, the shell entrypoint/`execute_no_trans`, the isatty ioctl, the app's unix-socket self-permissions) — plus two code fixes the loop forced: the `write_exec_context` `O_CREAT` elimination (LESSONS #31) and the NUL-termination in the attr-string parse that had broken the re-exec guard (LESSONS #30). A final verification pass also closed an intra-app *pipe* self-`fifo_file` gap the echo+cat+ls test never exercised (a shell pipeline is `apse_app_t → apse_app_t fifo_file`, not the host `unconfined_t` pipes; LESSONS #32). A follow-up **default_range** investigation (2026-10-29) corrected an early MCS assumption: a `dir`/`file`/`sock_file` created under the `s0` runtime parent takes the *parent's* low level (`default_range … target low` → `mls_context_cpy_low`), *not* the creator's `cN` — so the per-instance MCS isolates **processes** (a `cN` subject may only signal/ptrace/transition a same-`cN` process; a single category is incomparable with any other, *stronger* than podman's `cNNN,cMMM`), **not** files/dirs (those are all `s0`, reachable from any category) — the "first creator pins the session dir to `cN`" caveat was removed on that basis (LESSONS #29). The same pass found this kernel's `signull` (kill 0) is **not** in the base mlsconstrain and a module CIL cannot add one, so the `terminate_app` kill -0 probe is not category-scoped (LESSONS #33); the CIL grants `signull` where the probe needs it. A `apse_t → apse_app_t lnk_file read` grant closed the supervisor's `/proc/<pid>/cwd` resolution. The 8.5 threat-model review (done 2026-10-24, before enforcing mode) was re-checked against these findings 2026-10-29. The confined-mode field verification of the `dbus-proxy`/`xwayland` satellites and the broker — the last "what's left" item of the SELinux phase — completed 2026-11-04 under kernel 7.2.15 (v2.18; LESSONS #45-#46): the broker's consent flow, the dbus-proxy sidecar (plus its new stale-socket probe), and the Xwayland satellite (exec-time triple against the new SID, creator-SID grants on the inherited fds incl. `accept`, teardown signals, the `-auth` file lifecycle) all run with zero denials.) The local module confining the
      supervisor and app domains; the bind-mounted `/dev` nodes keep
      canonical labels, which makes this tractable — see §3.3).
      **container-selinux probe (2026-10-28, permissive):** apse run
      under podman's own types. Structural finding: podman uses
      *two* domains — `container_runtime_t` (crun, labeled
      `container_runtime_exec_t`, the `unconfined_t` exec transition)
      and `container_t` (the payload, reached by *setexecfilecon* —
      the policy has no file `type_transition` into `container_t` at
      all, only `process { dyntransition transition }` from
      `unconfined_domain_type`). Results: the S/A runtime side ran as
      `container_runtime_t` with **zero genuine denials** (rootfs
      rebuild mountons, fresh `/dev`+`/proc` mounts, cgroup scope
      create/enter/teardown, session-bus connect+send, the
      `system:start` of the transient scope, the instance dir, the
      scratch dir) — crun does exactly this work, so the shipped
      rules cover it; the full chain (the `--proxy` relay as
      `container_runtime_t` tagging into live sway, a sandboxed
      `wayland-info` through it) also ran clean. The app side ran as
      `container_t` with zero denials: the rebuilt rootfs' fresh
      `seclabel` tmpfs (`/tmp`/`/dev`/`/run`) inherit the creator's
      exec label → `container_file_t` for free (podman's own
      rootfs mechanism), and `/proc` reads, loopback net (UDP/TCP/
      DNS) and `/dev/urandom` are covered; `/dev/dri` via
      `container_use_dri_devices=on`. A live `podman run alpine`
      control logged zero denials too. What `container_t` alone does
      *not* cover is precisely the runtime-side set (the gaps above)
      — one item (`cgroup_t:dir` write/create) is
      `container_manage_cgroup`-gated (off by default; podman never
      needs it from the container side). Only artifacts: the dev
      binary in `$HOME` (`user_home_t`, a filecontext matter, not a
      gap) and `nnp_transition→mount_t` from the probe script execing
      `mount(8)` in-sandbox. Consequence: a zero-new-policy option
      exists (label the production binary `container_runtime_exec_t`;
      the whole tree then runs `container_runtime_t`); the custom
      module remains the cleaner shape (dedicated types), and this
      probe is the inventory the module must at least match — the
      `container_runtime_t` rules are the template for the runtime
      side, and the app side can stay minimal. **Decision #38
      (2026-10-28, amended):** the module stays custom (reusing
      `container_runtime_exec_t` rejected: it would leave the app in
      the more-privileged runtime domain, the label is third-party
      owned, and losing it degrades silently). It is **defined directly in CIL** (`selinux/apse.cil`) — the CIL is the policy source *and* the install artifact on this toolchain (Fedora 45, policycoreutils 3.11): the CIL reader lives in libsepol (the same library `semodule` links), not in the checkpolicy CLI, so a bare `(type …)`/`(allow …)`/`(typeattributeset …)` file with no `(module …)` header installs directly — proven by install. The earlier "CIL impossible" note was wrong (it tested the checkpolicy binary, which has no CIL input mode); see LESSONS #24-25. The classic `.te` → `checkmodule` pipeline was dropped (2026-10-29): `checkmodule -C` emits `typetransition` with the raw `.te` class (`file`) and does not normalize it to `process` the way the classic checkpolicy pipeline does, and the kernel's bprm transition lookup consumes only `process`-class entries — so hand-written CIL is both the fix and the simpler shape (LESSONS #27). The install is **`sudo semodule -i selinux/apse.cil` — one command for rules *and* file context**: on 3.11 the store reads file contexts straight out of the module CIL (libsemanage calls `cil_filecons_to_string` after `cil_compile` and writes the result into the policy's `file_contexts` — `libsemanage/src/direct_api.c`), and the two `(filecon …)` statements for the binary's label are embedded in the file, so the label is *in* the module and `semodule -r apse` removes it too. The CIL also states the two things the classic pipeline gets wrong for a user-spawned type: the `(roletype unconfined_r …)` association (a context is valid only when its role is associated with its type — without it `setprocattr` fails `EINVAL` and the MCS narrowing silently degrades, LESSONS #28) and the `mcs_constrained_type` membership that gives the categories their teeth. `apse_t` is based on the probe's AVC inventory
      (the deduped denials plus the three userspace-audit rules
      `audit2allow` could not see), trimmed of crun-only
      permissions; the probe's `mounton`-on-file and the
      `unconfined_dbusd_t`/`session_dbusd_tmp_t` session-bus types
      fed the rework (commit e5a407a). `apse_app_t` stays minimal
      on stock object types. **Per-instance MCS categories**
      (2026-10-28, `src/mcs.rs`): one category `cN` per instance
      within the user's `s0-s0:c0.c1023` range — a stable FNV-1a
      hash of app-id+instance-id, so the `run` pipeline and the
      standalone proxy/satellites agree. Every confined apse
      process (the `run` supervisor, the standalone proxy, both
      satellites) narrows its own range via a `apse_t`
      self-`dyntransition` re-exec **before** it creates or binds
      anything (the loop guard is range equality; a failed
      exec-context write degrades to a run without MCS); B and the
      Xwayland/dbus-proxy satellites carry the range into their
      execs via setexecfilecon (`apse_app_t`/`xserver_t` — the
      module gained `dyntransition` on both transitions), and the broker narrows to *single-level* `s0` (the same re-exec, `mcs::self_reexec_to_s0`) — a range-hygiene measure that keeps the broker's **subject** range minimal, so a compromised broker cannot act as a full-range subject or reach another instance's `cN` processes (an `s0` high does not dominate a `cN`). The session-level objects it serves (the runtime dir, `decision.sock`) are `s0` *by construction* (the parent's low level — `default_range … target low`), so they stay reachable from every `cN`; no pre-creating needed. SIGHUP
      re-execs preserve the range (an exec-context write that skips
      a pending explicit context). The category isolates the instance's **processes** — a `cN` subject may only signal/ptrace/transition a same-`cN` process (a single category is incomparable with any other, *stronger* than podman's `cNNN,cMMM`) — but **not** its **objects**: under `default_range … target low`, a `dir`/`file`/`sock_file` created under the `s0` runtime parent is `s0` (reachable from any category), so *file-level* separation between instances comes from the namespaces + landlock rootfs, not SELinux (LESSONS #29); the unconstrained socket/`fd` classes keep the broker protocol working. Verified 2026-10-29: a confined run reached `apse_t:s0:cN` / `apse_app_t:s0:cN` (the earlier no-narrowing failure was the missing `(roletype unconfined_r apse_t)`; LESSONS #28); the `signull` (kill -0) category gap is documented in LESSONS #33.)
- [x] 8.3 Update `AGENTS.md` (layout, facts): the header points at
      the rewritten README; the `systemd/user/` entry notes the
      broker units are the only units left (proxies are manual runs,
      sidecars would land here); the target fact drops the phase-7
      re-home as pending (7.1 done); the per-instance-dir fact gains
      the in-sandbox path translation and the app-env wiring
      (decision #28); the WIP bullet lists the true next steps.
- [x] 8.4 Integration test suite (`tests/`) (2026-10-24):
      `tests/sandbox_integration.rs` — eight tests driving the *built*
      `apse run` binary as a subprocess with a python3 probe as the
      app (all runnable as a regular user): identity (single-extent
      `uid_map`, PID 1, cgroup-ns root `0::/`, uts hostname,
      `setuid(0)` fails), the rebuilt rootfs (fresh `/dev` with only
      the standard nodes, `/sys` with empty `/sys/fs`, `/run` holding
      only the instance tree, fresh `/tmp`, namespaced `/proc`), the
      Landlock floor (seccomp filter active; a write denied outside
      the granted subtrees, allowed inside them, read-granted trees
      unwritable), the network (`shared` completes a ping/pong with a
      host-side listener; `none` denies `bind` and `connect` before
      the packet leaves — the bare netns per `/proc/net/dev` holds
      only `lo`), the tagged socket (the only one visible in the
      instance dir, the app's `connect(2)` succeeds, and the 5.4
      cleanup removes the per-instance runtime dir after the run),
      and the lifecycle (a forwarded TERM to a handler exits 0; an
      ignored TERM as pidns-init dies by the 2 s SIGKILL escalation,
      exit 137 after ≥1.5 s). The suite skips cleanly when python3,
      unprivileged user namespaces, a live wlroots compositor, or the
      systemd-standard session XDG is absent — the last because the
      supervisor builds its capability set against the *in-sandbox*
      instance-dir path (decision #28), which exists on the host only
      for that XDG (see LESSONS.md #22).
- [x] 8.5 Threat-model review against the old README's list, item by
      item (2026-10-24): reviewed the pre-8.1 README's threat model
      (README @ `1d780d5^`) against the in-process architecture.
      *What it protects:* **home files** — changed shape: the app is
      its real uid and keeps its *real* XDG dirs writable, so the
      protection is from other users and the system, not from you
      (the standard masks — other users' homes, `/root`, `/var`,
      `/srv`, `/media`, `/mnt` — still apply; 8.4 verified the floor
      empirically); **session D-Bus** — stronger: unreachable by
      default (the rebuilt `/run` carries only the instance tree and
      AF_UNIX `connect`/`bind` is trapped to it), with the `dbus-proxy`
      sidecar (7.2) as the opt-in filtered path; **privileged Wayland
      globals** — unchanged (compositor per-context policy via the
      tagged socket, plus the relay's `--allow-globals`); **privilege
      escalation** — stronger: the single-extent self-map leaves uid 0
      *unmapped*, so `setuid(0)` is `EINVAL` rather than merely
      capability-dropped (8.4 verified); **app code integrity at build
      time** — retired: the container-era GPG-verified images are gone;
      the app is whatever command `run` is given, and its integrity is
      the user's as for any local program; **the selection read-gate** —
      unchanged (the relay's opt-in receive-gate, with broker consent
      and the always-on audit log riding on it). *What it does NOT
      protect:* **outbound network** — same stance, with `--network=none`
      as a new explicit knob (8.4: bare netns, `bind`/`connect` denied
      before the packet leaves); **clipboard copy-out** — same
      tripwire + audit-log stance (the `start_drag` write-audit remains
      open as 6.5.5); **the shared downloads volume** — absorbed into
      the new "your own home directory" residual (the same cross-app
      tamper, scoped to your own uid's files); **GPU render nodes** —
      unchanged; **portal attribution** — unchanged, now via the
      *built* `dbus-proxy` (the "planned" wording corrected); **within
      a pod** — now "within one app instance" (all its processes share
      the instance namespaces; the 7.3 xwayland satellite is
      per-instance, so there is no display shared across instances).
      The **SSH/git guidance** survives (mechanism: the profile's
      `unix_sockets`); the container-era **SELinux caveat** (the global
      `container_t → wl_dbus_proxy` connectto rule, MCS-bounded) is
      retired — the 8.2 module scopes every rule to the `apse_t` /
      `apse_app_t` domains. The review retired the container-era
      known gaps (at-spi allow-nothing, the image-frozen SIGHUP
      re-exec, the missing `wl-app@.pod`, the GPG-chain TODO, the
      commented-out drop-in knobs) and fixed three stale entries in
      the current README: the multi-process "deadlock" gap (resolved
      by decision #32 — the supervisor services *every* trapped
      notification, Firefox e2e the proof; the remaining caveat is
      app-internal pipe behaviour), the "sidecars are later" bullet
      (7.2/7.3 are built), and the "full chain … (Phase 5.5)" bullet
      (5.5 is done — what remains is the sandboxed client through the
      `--proxy` relay into the live compositor). **Re-checked 2026-10-29
      against the enforcing-mode findings:** the SELinux module is now an
      *installed, tuned* containment layer (added to the README's
      "what it protects"), and two new residual-risk bullets landed in
      the README's "what it does NOT protect": (1) **SELinux MCS is
      process-level, not file-level** (created objects are `s0` under
      the `s0` parent via `default_range … target low`, so instances'
      files are *not* isolated from each other by SELinux — file/dir
      separation is the namespaces + landlock rootfs; LESSONS #29), and
      (2) the **`signull` (kill -0) category gap** (not in the base
      mlsconstrain, unfixable in a module CIL, minimal impact; LESSONS
      #33). The README's "known gaps" SELinux entry was rewritten from
      "first-pass, not installed" to "built, installed, tuned". Also
      corrected: the `start_drag` write-audit the 2026-10-24 review
      left open is closed (6.5.5 — a `start_drag` is audited as a
      write with its own copy-out notification), and the `serve`-
      label refinement for in-drag flow is closed too (v2.19 — the
      relay tracks the active drag source, so in-drag serves are
      labeled `selection=drag`).

## 8. Risks / things to watch

- **Kernel features on Fedora 45**: unprivileged user+mount+proc+devpts
  from a plain user session — Phase 1/2 verify tasks exist exactly for
  this (Fedora ships unprivileged userns enabled, but verify).
- **`uid_map` is write-once and, for us, single-extent (#9, #10)**:
  confirmed on 7.2.11-300.fc45 — the single-extent self-map works, the
  full ns cap set is held at exec, `setresuid(0)` is EINVAL, and the
  write-once probe (second write EPERM, map unchanged) passes. What
  remains of this risk: a subuid range for file ownership needs a
  setuid helper (`newuidmap`) if we ever want it — a later phase, not
  a blocker.
- **seccomp friction with GUI apps**: JVMs and browsers do exotic
  syscalls; nono's default is allow-everything-except-notified, which
  should keep friction low — but `strace`-driven tuning is expected in
  Phase 4.
- **nono API churn**: pin the version in `Cargo.lock`; the
  supervisor/prepare/apply split needs source-level reading in Phase 4
  (docs are thin; the source is the reference).
- **cgroup corner cases**: no-internal-process rule (we only *create*
  children, never enable controllers under a populated cgroup — safe),
  and how the user-slice delegation behaves in Phase 6.1 — fallback
  path covers any surprise.
- **Tagged-socket coverage is absent from CI (headless runner)**: the
  pre-fork `wp_security_context_v1` tag exchange runs against the
  session's live compositor (`sway`/wlroots), which the GitHub
  `ubuntu-latest` runner has none of, so the in-crate tagged test
  (`sandbox::tests::tagged_socket_is_carried_reachable_and_untagged`)
  and the integration test
  (`wayland_tagged_socket_is_the_only_socket`) skip via the same
  three-check predicate (empty `WAYLAND_DISPLAY`, non-standard
  `XDG_RUNTIME_DIR`, absent session socket). The tagged path itself
  (tag creation, the `security.context` xattr, reachability,
  untagging on teardown) is therefore only exercised on a live
  desktop, not in CI. A standalone future item: a small fake
  wlroots compositor that advertises `wp_security_context_v1`
  (accepts the `get_security_context` request, sets the socket's
  `security.context` xattr, returns the context) so the tagged path
  runs headlessly. Not a blocker for the current suite — the other
  sandbox tests need only the `run` pipeline, which works without a
  compositor.
- **AppArmor as the confinement layer (no-SELinux targets, e.g.
  Ubuntu/Debian)**: parked design sketch in `docs/apparmor.md`
  (2026-11-11). The baseline needs zero changes — the unconfined
  mode already works on AppArmor machines (CI's `ubuntu-latest`
  runner is one), so this is purely the phase-8.2-analogue second
  layer: three path-based profiles (`apse`/`apse_app`/
  `apse_xserver`), an exec-transition backend replacing
  `/proc/self/attr/exec` (write
  `/proc/self/attr/apparmor/current` +
  `prctl(PR_SET_SECURECOMPUTING, 1)`), and no MCS equivalent
  (accepted — the pidns already isolates the apps, and the
  host-side signal gap equals today's unconfined behavior). The one
  open question that shapes the work: whether AppArmor's exec hook
  sets `bprm->secureexec` on a `change_profile` transition (the
  same clear the pdeathsig shim exists for) — a 10-line probe
  answers it (§2.2 of the doc).