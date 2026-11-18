# apse SELinux module (phase 8.2)

A local SELinux module confining the apse stack to its own domains. The
enforcing-mode tuning loop is done (2026-10-29): audit2allow against a
confined run, iterated until confined `echo`+`cat`+`ls` produced zero
denials — the current rule set is that loop's output; future denials are
trimmed the same way ("Tuning loop" below).

## The policy is defined directly in CIL

`apse.cil` is the single source of truth and the install artifact: no
`.te`, no `checkmodule`, no build step. On this toolchain (Fedora 45,
policycoreutils 3.11) `semodule -i` accepts CIL directly (the CIL reader
is in libsepol, the library `semodule` links — the checkpolicy CLI has no
CIL input mode; LESSONS #24-25); the 3.11 module store is CIL-based even
for classic `.pp` installs. The old `.te` → `checkmodule -C` path was
dropped for three reasons:

- `checkmodule -C` writes `typetransition` with the raw `.te` class
  (`file`) and does not normalize it to `process` the way the classic
  checkpolicy pipeline does; the kernel's bprm transition lookup consumes
  only `process`-class avtab entries, so the transition silently never
  fires. Hand-written CIL spells `process` explicitly (LESSONS #27).
- The 3.11 module-store CIL dialect has no `filetrans` keyword: a
  filename transition is the *five-field* `typetransition` —
  `(typetransition src tgt class "name" child)`, the quoted name
  distinguishing it from the four-field process form; `filetrans` fails
  `semodule -i` with `Unknown keyword` (LESSONS #56).
- A hand-written CIL states the two things the classic pipeline gets
  wrong for a user-spawned type: the **role association**
  (`(roletype unconfined_r apse_t)` — the process inherits `unconfined_r`
  from the shell, and a context is only *valid* when the role is
  associated with the type; without it `setprocattr` on the exec context
  fails `EINVAL` and the MCS narrowing silently degrades, LESSONS #28) and the
  **`mcs_constrained_type` membership** that gives the categories their
  teeth.

The CIL reader accepts `;` line comments (the libsepol lexer's comment
rule matches `;`; the parser skips to end of line); otherwise the file is
bare statements.

## What it defines

Labeling mechanics for the dedicated dir types below: created inodes are
*not* labeled by `filecon` (`selinux_determine_inode_label` consults only
an mntpoint default, a process `create_sid`, or a filetrans) — they take
the filetrans result for (creator, parent, class), and the no-rule default
of `security_compute_sid` (the *parent's* own type) makes everything
beneath a filetrans-created root inherit its type: one rule labels the
whole tree, any depth, any fs. The range takes the parent's low level
(`s0`, dominated by every `s0:cN`). The *static* half: a `filecon`
registers the label `matchpathcon`/`restorecon` compute from the filecon
table alone (the filetrans is invisible to them); without one, a
`restorecon -R` drags the tree back to the broader base label.

- `apse_exec_t` — file type for the installed `apse` binary
  (`/usr/local/bin/apse` or `/usr/bin/apse`), a *standard application
  executable*. It carries the attribute set the base policy gives
  `ssh_exec_t`/`useradd_exec_t`/`sudo_exec_t` (`file_type`, `exec_type`,
  `entry_type`, `application_exec_type`, `non_auth_file_type`,
  `non_security_file_type` — see `seinfo -t apse_exec_t -x`), so unconfined
  gets the full file lifecycle (incl. `unlink`) by attribute; the only
  explicit grant is `entrypoint` (base gives it per-type; required for the
  `unconfined_t → apse_t` transition). No write grant on any of those
  attributes reaches `apse_t`/`apse_app_t`, so a sandboxed app cannot
  modify the binary.
- `apse_t` — supervisor / S→A→B pipeline / sidecar domain, reached by
  transition from `unconfined_t` when the binary carries `apse_exec_t`.
  Covers: rootfs mounts (fresh tmpfs / devpts / proc, self-bind of `/`,
  profile binds), the per-instance cgroup, the per-instance runtime dir
  and its sockets (wayland, X, bus, broker), the session bus (dbus-broker
  as `unconfined_dbusd_t`), the per-app private state tree (decision #43
  — the `apse` root dir under `~/.local/state`, bound over the app's
  home/XDG locations), spawning `xdg-dbus-proxy` and Xwayland, the
  namespace/userns/cap setup, the `/proc/self/exe` re-execs.
- `apse_app_t` — sandboxed-app domain. B execs the app while in `apse_t`;
  the app (and its subprocesses) land here via the
  `bin_t`/`shell_exec_t`/`apse_state_t` transitions and — since v2.32 — the
  dedicated-type app transitions (`mozilla_exec_t`/`hostname_exec_t`; the
  generic attribute-object form is infeasible — exec-world section).
  "Confined user app": instance dir, /tmp, /dev nodes, /proc /sys /cgroup
  /etc, home (`apse_state_t`, decision #43), system libs, session bus,
  loopback network, and `statfs` on every mounted filesystem type
  (`filesystem_type` — the `df` surface; tuning notes below). Its
  *self*-grants are the full base-policy `domain` set, mirrored
  explicitly (v2.25 — the tuning notes explain why the `domain` attribute
  itself is not joined), plus the domain baseline file read set *as
  written* on `base_file_type`/`base_ro_file_type` (v2.27; the v2.26 first
  cut on `non_auth_file_type` was judged overly broad and revised the same
  day). The dedicated /etc config types are in neither base set, so they
  show `????` in a confined `ls -l /etc` — an accepted least-privilege
  trade (task 8.10's per-instance hosts/hostname/resolv.conf binds are the
  substantive fix); the /proc/sys content closure stays intact.
- `apse_state_t` — the per-app state tree (`$XDG_STATE_HOME/apse/` — on
  Fedora `~/.local/state/apse/`), the home of decision #43. A dedicated
  type instead of the `gconf_home_t` the gnome module's filecon
  (`HOME_DIR/\.local(/.*)?`) incidentally gives to *all* of `~/.local`
  (everything but `.local/share`). Labeling: the named filetrans
  `(typetransition apse_t gconf_home_t dir "apse" apse_state_t)` (the
  mechanics above) and the static filecon (decision #46)
  `HOME_DIR/\.local/state/apse(/.*)?` → `apse_state_t` (the 3.11
  `HOME_DIR` keyword expands into `file_contexts.homedirs`, `system_u`
  into the user's selinux user; the deeper path beats the broader
  catch-all) — without the filecon the nearest match is the gnome
  catch-all and `restorecon -R` drags the tree back off `apse_state_t`. A
  *custom* `XDG_STATE_HOME` outside the default location is out of reach
  of any filecon — what S's relabel walk (`prepare_app_state` →
  `relabel_state_tree`, the `apse_shim_t` mechanism; confined mode only)
  self-heals, including a one-time migration of a pre-module
  (gconf-labelled) tree. Module types join no base attribute, so the
  tree's access is this module's grants alone: `apse_t` (creation, the
  0700 chmod, the setxattr relabel walk, the `mounton` A's private-home
  binds land on), `apse_app_t` (the full file lifecycle, incl. fish's
  `lock`/`watch` and the `entrypoint`/`execute` of private-home execs),
  `unconfined_t` (the user's own inspection; the test-suite pipeline runs
  unrelabeled).
- `apse_etc_t` — the per-instance `/etc` files (task 8.10):
  `hosts`/`hostname`, generated by A into the per-instance runtime dir
  (a `user_tmp_t` tree under `$XDG_RUNTIME_DIR/apse/<inst>/etc/`) and
  bound over the self-bind-layer `/etc` (step 7.5) so the instance's UTS
  name resolves on loopback without a DNS fallback. The named filetrans
  `(typetransition apse_t user_tmp_t file "hosts"|"hostname"
  apse_etc_t)` labels the inodes at birth, so A's 0644 chmod and the
  teardown's removal check this type, never `user_tmp_t`. The kernel's
  `may_create` (`selinux_inode_create`) also checks `filesystem:associate`
  of the *new label's* SID against the containing dir's superblock — hence
  the `tmpfs_t`/`fs_t` pair (`/run` is a tmpfs; `fs_t` covers an
  off-default XDG on a real filesystem). Access: `apse_t` (create, write,
  setattr, unlink, …), `apse_app_t` read-only (getattr/open/read),
  mirroring the unconfined floor's `Read`-only Landlock file grants, and
  `unconfined_t` getattr/unlink. The bind targets are the host's
  `net_conf_t` (`hosts`) and `hostname_etc_t` (`hostname`): `apse_t`
  needs `getattr` (the build's target-exists check stats them) and
  `mounton`.
- `apse_xsocket_t` — the `x/` subdir of the per-instance runtime dir
  (decision #47): the home of the X socket and the MIT auth file the
  `xwayland` satellite places there (`$XDG_RUNTIME_DIR/apse/<inst>/x/`, a
  `user_tmp_t` tree). The dedicated type exists so the satellite's
  `xserver_t` needs no allow rule between two base types (pre-change:
  `xserver_t → user_tmp_t` for the auth file and the socket). Labeling:
  the named filetrans `(typetransition apse_t user_tmp_t dir "x"
  apse_xsocket_t)` (the satellite is `apse_t` in confined mode) plus a
  static filecon (`/run/user/%{USERID}/apse/[^/]+/x(/.*)?` — `%{USERID}`
  is the 3.11 template keyword the store expands per user into `[0-9]+`,
  the same route as the dbus/gnome modules' own `/run/user` entries; the
  deeper path beats any broader `/run/user` catch-all). The *socket file*
  is the one exception: on `bind(2)` the kernel's `selinux_sock_graft`
  (PF_UNIX) copies the socket object's SID — the creator's, `apse_t` —
  onto the bound inode, and the object keeps that SID for its life, so the
  file and every socket-class check on it land on `apse_t`, not here;
  `xserver_t` therefore holds the listener purely by fd (`fd:use` on
  `apse_t`, an existing rule) and never opens the socket by path — no
  `sock_file`/`unix_stream_socket` grant on `apse_xsocket_t` at all. A
  stale pre-filetrans `x/` (new binary, old module) is healed by the
  satellite: it liveness-probes the socket (a live X server is never
  disturbed) and remove+recreates the dir, so the filetrans labels the
  replacement — no `relabelto` grant needed. Access: `apse_t` (creation,
  the 0700 chmod, the stale-dir remove+recreate, teardown), `xserver_t`
  (the auth file only: create/write — module→module), `apse_app_t`
  (read-only: dir traversal and reading the auth file; the app reaches the
  socket by path — `connectto` on the existing `apse_app_t → apse_t`),
  `unconfined_t` (the user's own inspection and cleanup).
- `xserver_t` — stock policy transitions `unconfined_t → xserver_t` on
  `xserver_exec_t`; in confined mode the satellite is `apse_t`, so the
  module adds the `apse_t → xserver_t` transition plus `xserver_t` access
  to the X socket and MIT auth file it places in the `x/` subdir
  (decision #47): the auth file is `apse_xsocket_t` (a module→module
  grant — the point of the dedicated type; the pre-change rules hit
  `user_tmp_t`), and the socket file is `apse_t` (the
  `selinux_sock_graft` above), held purely by fd (`fd:use` /
  `unix_stream_socket` on `apse_t`, existing rules). Precautionary — the
  Phase 7.3 e2e logged no denials.

**Roles:** both `apse_t` and `apse_app_t` are associated with
`unconfined_r` (the spawner's role, as container-selinux does with
`container_t`/`container_runtime_t`) *and* with `object_r` (so their file
labels are valid). The `unconfined_r` association is load-bearing — see
above.

## Operating modes

**Unconfined mode (default, no action needed).** The binary keeps its
usual label; nothing transitions; the whole stack runs `unconfined_t`
exactly as before, and the module is inert.

**Confined mode.** Relabel the installed binary so the transition fires:

```sh
sudo restorecon -v /usr/local/bin/apse   # picks up apse_exec_t
```

After that every `apse` subcommand runs as `apse_t`; the sandboxed app
and the helpers it or the pipeline exec run as `apse_app_t`; Xwayland
runs as `xserver_t`. The hard boundary of the sandbox is still the
namespaces + nono landlock/seccomp (decision #27) — the module is a
second, compositable layer.

**Per-invocation opt-out (task 8.6, `--no-selinux`).** A confined
binary can run *one* invocation outside the module without any
relabeling: the flag (or the `APSE_NO_SELINUX` env var, any non-empty
value other than `0`) makes `main` write the pre-module exec context
— the binary's stock type (`unconfined_t`, whatever a never-relabeled
install carries) with the process's current range — to
`/proc/self/attr/exec` and re-exec `/proc/self/exe` with the original
argv, once, *before* the MCS narrowing (an exec context can only
*narrow* the range, so the full-range stock context must be written
first). From there the whole pipeline and the app behave exactly as in
the unconfined mode above — no MCS, no shim, no exec-context writes,
the app keeps its own file label — while every other confinement (the
namespaces, the rebuilt rootfs, Landlock, the seccomp filter) stays
and the system's SELinux enforcement is untouched. The module grants
one rule for it (the `apse_t → unconfined_t` process allow in
`apse.cil`: `transition` for the SID change, plus `noatsecure` /
`rlimitinh` / `siginh` — the same trio the MCS self-narrowing
re-exec gets from the `apse_t` self-grant; a self-exec of the same
non-setuid binary is not a privilege change, so it is deliberately
not run in secure mode. The `file:entrypoint` side is the stock
launch grant, and no `type_transition` rule is needed because an
explicit exec context bypasses the transition table). The loop guard is the type check
itself: after the re-exec the label is no longer `apse_t`, so a second
pass is a no-op. In unconfined mode (the binary not relabeled) the
flag is a no-op. If an app binary carries a type other than
`bin_t`/`shell_exec_t`/`apse_state_t` (check with `ls -lZ <app>`), add a
`(typetransition apse_t TYPE process apse_app_t)` line (plus the matching
process/file allows) to `apse.cil` and reinstall.

## Per-instance MCS (process-level isolation)

In confined mode, each app instance gets its own MCS category within the
user's `s0-s0:c0.c1023` range (a stable FNV-1a hash of app-id +
instance-id). What that category actually isolates is the **process**
level, *not* the object level — the two behave differently under the live
policy's `default_range` rules (LESSONS #29):

- **Processes are isolated, per-instance.** A `process` takes its
  creator's *full* range (the `process` class has *no* `default_range`
  rule, so `mls_compute_sid` falls through to `AVTAB_CHANGE` →
  `mls_context_cpy`), so every stage of the S→A→B pipeline, the app, and
  the satellites run at that instance's `cN`. Both `apse_t` and
  `apse_app_t` are members of the base `mcs_constrained_type` attribute,
  so the base mlsconstrain (`h1 dom h2 or t1 != mcs_constrained_type`)
  applies: a `cN` subject may signal/ptrace/transition only a process
  whose level it dominates, and a *single* category is incomparable with
  any other — `cN` dominates only `cN`. Cross-instance
  `sigkill`/`sigstop`/`ptrace` are therefore denied (a `cM` process is
  simply not reachable from a `cN` subject). This is *stronger* than
  podman's `cNNN,cMMM` two-category model, where a container's level
  contains a *set* of categories that orders against other sets; here one
  category dominates only itself. One gap: this kernel's process class
  splits `signal` into `signull` (kill 0), `sigkill` and `signal`, and the
  base mlsconstrain constrains all of those **except** `signull` — so a
  kill -0 (used by `terminate_app`'s liveness probe) is *not*
  category-scoped (LESSONS #33); it cannot be closed in the module,
  because libsepol's CIL reader rejects `mlsconstrain` in a module CIL.
- **Objects are *not* isolated, per-instance** — with one exception. A
  `dir`/`file`/`sock_file` created under the user's runtime dir takes the
  *parent's* low level, not the creator's range (`default_range …
  target low` → `mls_context_cpy_low(newcontext, tcontext)`), and the
  parent (`/run/user/<uid>`) is plain `s0`. So the instance dir, the
  build scratch, and every per-instance socket are all `s0`, and any
  `cN` (or `s0`) subject dominates `s0` — every instance and the broker
  may read and write them. There is **no** MCS file/dir separation
  between instances: *content* isolation comes from the namespaces +
  landlock rootfs (each sandbox sees only its own instance dir), not
  from SELinux. The `socket` and `fd` classes are also **not** in the
  base constrain list, so the broker's session sockets and inherited fds
  keep working across categories. **Exception (decision #48):** the
  `x/` subdir of the instance dir (the X socket + MIT auth file) is
  explicitly relabelled by the `xwayland` satellite to the instance's
  `cN` (`apse_xsocket_t:s0:cN`). Because the `default_range` rule copies
  the *parent's* low level, the X socket and auth file created inside it
  inherit `cN` for free. This makes the MIT auth file (which grants
  X11 authentication) per-instance: a `cM` subject cannot read a `cN`
  object (`cM` and `cN` are incomparable). The `xserver_t` process
  itself also runs at `cN` (typetransition from the satellite's `cN`
  range), so the X server can read its own auth file. The satellite
  self-heals on restart: if the dir is at the wrong level (e.g. after a
  `restorecon`), it relabels it back to `cN` via `setxattr`. `filecon`
  pins only the *type* (`apse_xsocket_t`); the runtime level is not
  expressible in a static filecon.

Mechanics (`src/mcs.rs`):

- at startup, if the process label is `apse_t` (confined) each process
  narrows its own range to the instance's single-level `s0:cN` (the code
  writes a low==high `s0-s0:cN`, reported canonically by the kernel as
  `apse_t:s0:cN` / `apse_app_t:s0:cN`) by writing `/proc/self/attr/exec`
  and re-exec'ing `/proc/self/exe` (the self-`dyntransition` on `apse_t`).
  The kernel accepts the write only if the
  target context is *valid* (role associated with type — the
  `unconfined_r` roletypes above) and the new range is a subset of the
  current one (the base `context (contains)` constrain). The narrowing
  happens **before** any binding/creation, so every forked child inherits
  `cN`; objects created under the `s0` parent stay `s0`.
- B carries the range into the app exec via setexecfilecon
  (`apse_app_t:s0:cN`); the Xwayland and dbus-proxy satellites do the same
  for their execs.
- the broker (shared by all instances) narrows to *single-level `s0`*
  before it binds or creates anything (`mcs::self_reexec_to_s0`, the same
  re-exec, run before the listener is taken). The session-level objects it
  serves (the `$XDG_RUNTIME_DIR/apse` session dir and `decision.sock`) are
  `s0` *by construction* (the parent's low level), so they are reachable
  from every category regardless of who creates them first. The narrowing
  is a *range-hygiene* measure: it keeps the broker's **subject** range
  minimal (a single `s0` level rather than the full spawn range
  `s0-s0:c0.c1023`), so a compromised broker cannot act as a full-range
  subject or reach another instance's processes (an `s0` high does not
  dominate a `cN`).
- SIGHUP re-execs preserve the range (an exec-context write that skips any
  pending explicit context, so the startup narrowing is never clobbered).
- a failed exec-context write degrades to a run **without** MCS: logged,
  the run continues. In unconfined mode the mechanism is off (labels have
  no category to carry).

## In-sandbox debugging (task 8.7, v2.33)

A **two-layer gate** with **AND** semantics, because SELinux has no
per-invocation policy (policy is global kernel state; a per-invocation
*grant* is impossible — the type is a property of the file, not of a run):

- **Per-sandbox: seccomp (the default on).** For every run *without*
  `--debug`, B installs a **second, stacked classic-BPF seccomp filter**
  after nono's notify filter that rejects the `ptrace` syscall with
  `EPERM`; everything else is `SECCOMP_RET_ALLOW` (falls through to
  nono's filter — filters evaluate newest-first). Invisible to SELinux and
  per-run by construction: `apse run --debug` skips it for that one run,
  and the process shows `Seccomp_filters: 1` instead of `2`.
- **Global: the boolean `apse_app_ptrace` (default off).**
  `(boolean apse_app_ptrace false)` plus a boolean-gated **self**-grant
  `(allow apse_app_t apse_app_t (process (ptrace)))` — a self-grant,
  because the debugger (strace/gdb) execs into `apse_app_t` exactly like
  its target. Toggling is root-only (an unprivileged `setsebool` is
  `EACCES`): `sudo setsebool -P apse_app_ptrace on`.

`apse run --debug` in confined mode reads the boolean unprivileged (a file
read: `/sys/fs/selinux/booleans/apse_app_ptrace`, `<value> <state>`)
**before building anything** and fails fast with an actionable message when
it is off or absent (the module is too old). In unconfined mode the check
is a no-op and the flag stands on the seccomp gate alone. The
supervisor-side read needs its own grants: selinuxfs is labelled
`security_t`, so the module allows `apse_t` `dir { search getattr }` and
`file { open read getattr }` on it (LESSONS #79).

Usage is **same-instance by construction**: the debugger *is* the app
(`apse run --debug -- gdb ./target` — it forks+execs and ptraces its own
child via `PTRACE_TRACEME`) or attaches within one instance (`apse run
--debug -- sh -c 'app & strace -p $!'`). A *separate* instance cannot debug
another one: its processes carry a different `cN` (the MCS section — a
single category is incomparable with any other, and the base mlsconstrain
on `process:ptrace` denies it), and disjoint PID namespaces mean the target
isn't even visible. Use the host-side path for that.

**Host-side debugging is a different trust line and is unaffected:**
`unconfined_t → apse_app_t` carries `ptrace` (the "user can trace" allow),
and the user's own clearance range (`s0-s0:c0.c1023`) dominates any single
`cN`, so `strace -p` / `gdb -p` from an unconfined shell attach to a
sandboxed app as before. Verified in enforcing mode (v2.33): the two layers
are independent — boolean on without `--debug` still denies via the seccomp
gate, while `--debug` with the boolean on attaches on both the `TRACEME`
and `ATTACH` paths with zero denials. The `signull` (kill 0) gap in the
base mlsconstrain (the MCS section) is unchanged by this task.

## The dedicated-type exec world (task 8.8, v2.32)

The `ip`/`hostname` denial class: the distro labels most of the ~2,600
user executables with per-purpose *dedicated* types (`ifconfig_exec_t`,
`hostname_exec_t`, `ping_exec_t`, … — 141 distinct types in the
bin/libexec trees here), and the module originally covered about three of
them, so an in-sandbox shell could not even *start* the tools
(`file:execute` denied at two levels: B's exec of a dedicated-type *app*,
and an in-sandbox shell's exec of such a *child*; `route` always worked
because it is `bin_t`). The fix is a grant on the base policy's
**`application_exec_type` attribute**, at both levels:

- **child level** (`apse_app_t`): the full exec union
  (`entrypoint execute execute_no_trans getattr map open read ioctl`) on
  `application_exec_type`;
- **app level** (`apse_t`): the same union minus `ioctl`. It absorbs the
  former per-type file rules on `xserver_exec_t` and `apse_exec_t` (both
  members of the attribute); their transitions stay.

**Why `application_exec_type` and not the wider `exec_type`** (the
original plan) — a refinement that inverts the attribute's apparent meaning
(LESSONS #76): on this system the attribute is the *dedicated* set — 311
compiled members, a strict subset of `exec_type`'s 1048. What it excludes
is exactly what a real-uid app should never exec: init scripts, server
daemons, inetd services — **plus the generic catch-alls** `bin_t` /
`shell_exec_t` / `usr_t`, which are `exec_type` members but *not*
`application_exec_type` members (they cover the other ~91% of
world-executables). Those three keep their enumerated rules, so nothing
about the generic tools (foot, htop, less, `sh`) changes; the union of
attribute + catch-alls is "everything but the daemon/init dedicated
types". The `exec_type` variant would only have bought a slimmer rule list
(net −6 vs ~0 here) at the cost of exec surface over 737 extra types that
are DAC root-only for a real-uid app anyway. Membership oracle: `seinfo -a
<attr> -x` (this `sesearch` does not resolve attribute membership in rule
queries).

**Setuid-stripping invariant (both levels):** neither grant carries
`noatsecure`. Exec of a setuid binary then triggers secure-exec and the
kernel leaves the euid at the caller's (1000 — the setuid bit is inert).
`su` (`su_exec_t` is a member) *execs* inside the sandbox but its
privilege machinery fails — PAM cannot authenticate, because its helper
`unix_chkpwd` is itself setuid-root and equally stripped — no escalation.
`pkexec` (`pkexec_t` is *not* a member) stays denied outright. DAC remains
the backstop either way: the app reaches only files it can already read as
its real uid.

**The app transitions stay enumerated** (one line per dedicated-type app
actually run — `mozilla_exec_t` (Firefox) and `hostname_exec_t` (the
standing probe) were added in v2.32). A *generic* attribute-object
`typetransition` is infeasible, not merely unverified (LESSONS #77): the
transition table is single-valued on (subject, objtype, class), and
`xserver_exec_t` is an `application_exec_type` member that must keep its
own `xserver_t` target (the Xwayland satellite) — a 311-member expansion
collides with it at install. The transitions also matter as the fallback
when B's one-shot exec context (`setexecfilecon`) is unavailable (a
no-match exec would keep B's own `apse_t` context — the supervisor's
grants — instead of landing in `apse_app_t`).

**The functional wave the tools then need** (per tool, the second half of
8.8): `ip` — `process:setcap` (iproute2's startup `capset(2)`: always
self-targeted — the syscall has no target pid — and privilege-neutral here:
the process holds no permitted capabilities, so it can only clear or
permute) and a `netlink_route_socket` self-grant (`bind create getattr
nlmsg_read nlmsg_write read write setopt`). Kernel details (LESSONS #78):
this 7.2 kernel's netlink classes carry *separate* `nlmsg_*` permissions —
recvmsg checks `nlmsg_read`, sendmsg `nlmsg_write` (plain `read`/`write`
is not the check); `getsockname` is the distinct `getattr`; and with no
`sockcreate` filetrans in play a socket is born in the *creator's* context,
so the whole grant is self-targeted and MCS-bounded. `hostname` (get mode)
needed nothing beyond exec (the read path has no MAC check), and the **set**
mode is intentionally not granted (the UTS hostname is the instance's
private identity). Deliberately *not* granted: `ping`/`traceroute`-class
raw and ICMP sockets (packet-sniffing in a shared netns — a separate policy
decision), `netlink_audit_socket` (8.7's business), and `journalctl`'s
journal reads (the fresh `/run` carries no runtime journal; the persistent
one is host data). The narrow `exec_type:file:getattr` rule stays — now
*precisely* the stat() path for the `exec_type` remainder outside
`application_exec_type` (the daemon/init trees, e.g. `ls -l /usr/sbin`).

## Denial-tuning notes (2026-11-12 round)

The grant set above is the output of four user-reported enforcing-mode
rounds (the original, 2026-10-29; then `df` + `ls -la /dev` + interactive
fish; the `/proc` self links, `/proc/net`, and the top-level `/proc`
entries; and the attribute-based redesign of that top-level stat) and a
fifth *proactive* completeness pass (v2.25) that re-audited the app's
*self*-grants against the base policy's own `domain` set instead of
waiting for a denial. Each bullet: phenomenon → root cause → grant.

- **`statfs`/`df` targets the *filesystem*, not the file.** `df` (even
  with an explicit path) stats the root of every mount it sees; the
  `statfs(2)` check runs against the **mounted filesystem's** type — the
  `filesystem` class, the `filesystem_type` attribute family (`tmpfs_t`,
  `device_t`, `fs_t`, `proc_t`, `sysfs_t`, `cgroup_t`, …) — never the path's
  label. `getattr` here is superblock metadata (fs type, size, free) — no
  content — so one attribute grant covers every mount the app may stat.
  `df` also stats `/proc/sys/fs/binfmt_misc` to detect that mount:
  `/proc/sys/fs` is its own `sysctl_fs_t` type (like
  `sysctl_kernel_t`/`sysctl_vm_t`), granted `search` + `getattr`.
- **`l??????????` = a missing `lnk_file:getattr`.** The sandbox's
  `/dev/ptmx` is a relative symlink in the *fresh* tmpfs (decision #39),
  so it carries the tmpfs default `tmpfs_t`, not `ptmx_t`. A listing does
  two separate checks on a symlink: `lnk_file:getattr` (the lstat of the
  *link itself* — what produces the target name) and `lnk_file:read` (the
  readlink). Without the getattr, getdents still knows it is a link, so the
  entry prints `l??????????` with no target. The same split applies to
  *self*-labeled links (the pident links of `/proc/<pid>` — #64) and to
  links whose *target* has a different type (`/proc/net` — #65): the
  readlink is `getattr` + `read`, not `read` alone.
- **Per-purpose exec types are not `bin_t`.** Fedora labels most of
  `/usr/bin/*` and `/usr/libexec/*` with per-purpose types (`lvm_exec_t`,
  `iptables_exec_t`, `systemd_systemctl_exec_t`, `fsadm_exec_t`, …); a
  `bin_t` grant reaches only the rest. For tools that stat every enumerated
  entry (fish's completion), the target is the **`exec_type` attribute**
  (the superset of every `*_exec_t`): `file:getattr` on the files,
  `lnk_file:(getattr read)` on the symlinks among them.
- **`open` and `read` on a dir are separate.** A tool that maps its
  controlling tty back to a `/dev/pts/<N>` name (fish) `opendir`s the
  (fresh, per-instance) devpts root — `dir:open` plus `dir:read`
  (getdents) — not just `search`. The same open/read pair is what the
  `proc_t`/`sysfs_t`/`sysctl_*` enumeration targets need (LESSONS #54,
  #59).
- **`/proc/<pid>` links are *self*-labeled — the grant is a self grant.**
  The whole `/proc/<pid>/` pident tree carries the *target process's own*
  context (LESSONS #45), so a sandboxed app listing its own `/proc/self`
  hits `apse_app_t:lnk_file` — the grant is `apse_app_t` → `apse_app_t`
  (`getattr` + `read`, the split above; #64). MCS-bounded in effect: a
  `s0:cN` subject dominates only same-category objects, so it cannot reach
  another instance's pident links. The *top-level* self links
  (`/proc/self`, `/proc/thread-self`, `/proc/mounts`) are a different case:
  the genfs rule labels them `proc_t`, so they take `getattr` + `read` on
  the `proc_t:lnk_file` grant.
- **`/proc/net` is a relative symlink — the link and the content are
  different types.** `/proc/net` → `self/net`: the link is `proc_net_t`
  (genfs), following it lands in the process's *own* net directory
  (self-labeled `apse_app_t`), whose files (`dev`, `arp`, …) are
  `proc_net_t` again — three layers, three grants: `lnk_file:(getattr read)`
  on the link, `dir:(getattr open read search)` on the self-labeled
  directory (covered by the existing self grant), and `file:(getattr open
  read)` on `proc_net_t` for the content. Read-only: the content is network
  state (a private netns in the sandbox — loopback only); no write granted.
- **Top-level `/proc` entries are targeted by the base-policy attributes,
  not by type.** Not everything is `proc_t`: the `/proc/*` genfs entries
  carry the **`proc_type`** family (`proc_t`, `proc_net_t`, `proc_kcore_t`,
  `proc_kmsg_t`, `proc_mdstat_t`, `proc_psi_t`, `proc_afs_t`,
  `proc_security_t`, `system_map_t`, `proc_numa_t`, …) and the
  `/proc/sys/*` subtree the **`sysctl_type`** family (`sysctl_t`,
  `sysctl_irq_t`, `sysctl_kernel_t`, `sysctl_vm_t`, `sysctl_fs_t`, …) — the
  same two attributes the base policy itself uses for exactly this surface
  (`kern_unconfined` and `container_userns_t` each target `proc_type` once,
  never per type). `ls /proc` stats every entry, so the grant is `getattr`
  per class on each attribute (`file`/`dir`/`lnk_file` — the CIL reader
  takes one class per `allow`, LESSONS #67), which covers *current and
  future* entries with no new rule; content access (`open`/`read`) stays
  per-type and deliberately excludes `kcore` (kernel memory) and `kmsg`
  (the kernel log). The one `/proc` type in neither attribute —
  `mtrr_device_t` (`/proc/mtrr`) — keeps a single-rule `getattr`.
- **The app's self-grants are the base policy's own `domain` set, mirrored
  explicitly — `apse_app_t` does *not* join the `domain` attribute
  (v2.25).** A line-by-line audit of `domain.te`'s self-grants (the macro
  expansions, spelled out literal — raw CIL has no macros) showed the
  earlier denial-driven rounds had built the mirror incrementally with four
  holes: `dir` missing `lock`/`ioctl` (`list_dir_perms`) and `watch`
  (`watch_dir_perms`), `lnk_file` missing `ioctl`, `file` missing
  `lock`/`ioctl` (`rw_file_perms` — flock on its own files, the lockfile
  pattern), and the fifo grant was the non-fips `rw` set while this box has
  `fips_mode` *on* (the variant giving domains `manage_fifo_file_perms`).
  The CIL block is now a complete line-by-line mirror — dir, lnk_file,
  file, fifo (the `manage` superset: mkfifo, open, chmod, rename, unlink —
  a shell's *named*-pipe case on top of the anonymous-pipeline
  `fstat`/read/write one), sem and shm (the literal `create_*_perms`
  expansions — *those classes have no `ioctl`*; a `Failed to resolve
  permission ioctl` from `semodule -i` is the detector), process (plus
  `getcap`), `fd:use` (`domain_fd_use`, on) and `key:{link search}`
  (`hide_broken_symptoms`) — with one deliberate omission: `fips_mode`'s
  only non-self rule, `kernel_read_kernel_sysctls` (a /proc/sys *content*
  grant; the /proc design above keeps content closed until a denial asks
  for it).
  The `domain` attribute itself: investigated (the `container_t` example —
  a rootless podman process is `domain`-labeled, `s0:cNNN,cMMM`) and
  rejected (full audit is the comment block in `apse.cil`). It is
  two-sided; the side that matters is where `domain` is the *subject*.
  Joining adds every active `domain → X` rule to the app — 121 across 74
  host types (126/76 counting rules gated by off-tunables): `dir`/`file`/
  `lnk_file` reads, `context translate` (+its socket) to `setrans_t`,
  `connectto` + `dbus send_msg` to `systemd_resolved_t`, `system
  module_request` to `kernel_t` (`domain_kernel_load_modules` on),
  `process {sigchld signull}` probes, and socket-receive grants. That is the
  app→host *escape* direction — the asymmetry the sandbox exists to enforce
  (the intended direction is the reverse: the host user may kill the app,
  as with a rootless podman container, but the app never reaches the host).
  apse's primary controls are all built by apse itself in one process tree,
  and the app runs as its *real* uid (no uid mapping, decision #9) — it
  lacks podman's uid-isolation safety net — so the module is the
  *independent second layer* (defense in depth): pre-emptively granting the
  full `domain` subject-side reach would disarm that backstop the moment a
  primary control (ns/seccomp) has a hole. The *other* side (`X → domain`,
  851 active rules, e.g. `unconfined_domain_type → domain: process {signal
  sigkill …} file … socket …`) is the host→app direction and is fine by
  design — *not* a reason to reject the attribute (the host user managing
  its own app is the podman model; joining would simply broaden our audited
  `unconfined_t → apse_app_t: process …` line into the full surface, within
  the same-user threat model). The base process neverallows are *not* a
  blocker: FSP 45.24's `domain.te` carries three (`domain →
  ~domain:process {transition dyntransition}` at :59 and two wider at
  :116-117), but the installed policy enforces none (the module's own
  transitions sit in their covered directions and have loaded cleanly in
  enforcing since v2.13 — a violation would be refused at `semodule -i`),
  and joining adds none (the module declares no transition from
  `apse_app_t` as subject). The remaining reason is maintenance: **base
  drift** — a future `domain.te` change (a tunable flip, a new grant) would
  reach the app silently; the explicit mirror is audited in the enforcing-
  mode tuning loop (a denial → a grant). Every self-grant is MCS-bounded in
  effect (a single-level `s0:cN` subject dominates only same-category
  objects).
- **The broad `file_type:* map` grant is dropped (v2.28): on this kernel
  the plain `mmap()` path enforces no file permissions — `open()` is the
  gate.** The v2.25 pass modeled `mmap(2)` on the pre-7.2 `file_mmap` hook
  (checked per *protection* — `read`/`write`/`execute` against the mapping's
  prot bits — with only the PROT_NONE case `map` ungranted; the body of the
  base's *off* `domain_can_mmap_files` tunable — `getsebool` is
  authoritative, the sesearch `:True` annotation is the condition's
  polarity) and granted `map` on the whole `file_type` family. A v2.28 A/B
  disproved that model on kernel 7.2.15-300.fc45: a probe running as
  `apse_app_t` (confinement proven in the same run: its `O_RDWR` open of a
  `usr_t` file is *denied*) mmaps an `etc_t` file private with all four
  prots (READ/WRITE/EXEC/NONE); all succeed with **zero AVCs** although
  `apse_app_t` has none of `read`/`write`/`execute`/`map` on `etc_t` — the
  broad grant was inert. (The vanilla 7.2.15 source *does* wire the 7.2
  replacement hook — `mmap_file`, a `FILE__MAP` check plus
  `file_map_prot_check`, `security/selinux/hooks.c` — into the `mmap()` and
  `mremap` paths, `do_mmap` itself carrying the "we assume access
  permissions have been handled by the open" comment; the running Fedora
  build's observed behavior differs, and the debug kernel package ships
  headers only, so the running code cannot be diffed locally — LESSONS #71.)
  The drop is a user call: too broad as a default position (`file_type` is
  the whole file class; the only `domain`-side precedent in the base is the
  *off* tunable). The per-type `map` grants (tmp_t, user_tmp_t, the state
  tree, self) stay — the `domain.te` shape, and they cover the paths the
  hook is wired to in the vanilla source. Revisit the broad grant on an
  *actual* `map` AVC — a future kernel/Fedora update that re-enforces the
  check on the plain path is the likely source.
- **Layering: the seccomp floor (decision #25) decides before SELinux, and
  one granted permission is unreachable on this kernel (v2.25).** The fifo
  `manage` set above includes `create` (mkfifo) — installed and
  `sesearch`-verifiable, but the *syscall* is auto-rejected by nono's
  seccomp floor (it is not in nono's allowlist) *before* the SELinux check,
  so in a live sandbox it fails EACCES with **zero AVC denials** — a
  zero-AVC EACCES in the sandbox means "seccomp floor", not "SELinux". The
  v2.25 verification therefore ran a purpose-built probe that exercises each
  grant directly (24 checks: getpcaps, a dup'd fd, sem/shm lifecycles incl.
  `SHM_LOCK`, inotify `watch`, `flock`, an `O_PATH` `getattr`/readlink, RW
  and PROT_NONE `mmap`s of files (now known vacuous on this kernel — the
  `map` bullet), and `ioctl` via a *made-up* command number —
  `security_file_ioctl` fires at syscall entry, at the top of
  `SYSCALL_DEFINE3(ioctl)`, before `do_vfs_ioctl` dispatch and any
  `FMODE_PATH`/command filtering, so it is the only way to exercise
  `ioctl` on a symlink's fd). The other reachability fact the mirror
  documents rather than tests: `lnk_file:lock` is granted (the `domain.te`
  shape) but no unprivileged process can ever hit it — the only fd to a
  symlink is `O_PATH` (a final-component `O_NOFOLLOW` open is ELOOP;
  `open_by_handle_at` needs `CAP_DAC_READ_SEARCH`), and every locking path
  (`flock`, `fcntl F_SETLK`/`F_OFD_*`) rejects an `FMODE_PATH` fd with
  EBADF *before* the LSM check.

Not fixed (deliberate, 2026-11-12): the `find /` class — a whole-filesystem
traversal produces thousands of `getattr` on the root-level dir types and
on the per-purpose exec types under `/usr`. If it is ever wanted it needs a
much broader root-dir surface, not more per-type grants — left as a user
decision. The same deferred class: fish's completion *executing* (not just
stat-ing) the enumerated admin tools (`bootloader_exec_t`, `mount_exec_t`,
`rpm_exec_t`, `lvm_exec_t`, `admin_passwd_exec_t`, …) — an `execute`
denial, a far broader surface than the read-only `exec_type` grant above —
and the metadata sweeps (`getfattr -R` over `/sys`/`/etc`/`/usr`; a python3
readlink sweep over `/usr/share/man` — `man_t:lnk_file:read`). Exploration
tools, not sandbox use cases.

## Install (needs root)

One command for the rules *and* the file context:

```sh
sudo semodule -i selinux/apse.cil
sudo restorecon -v /usr/local/bin/apse     # confined mode (see above)
```

The CIL carries four `(filecon …)` statements: two for the binary
(`system_u:object_r:apse_exec_t:s0` — the MCS category is a *process*
label, never a file label), one for the per-app state tree (decision #46),
and one for the `x/` socket subdir (decision #47). On 3.11 the store reads
file contexts straight out of the module CIL (libsemanage calls
`cil_filecons_to_string` after `cil_compile`, then `semanage_split_fc`
routes the entries carrying a template keyword (`HOME_DIR`, `%{USERID}`) to
the separate `file_contexts.homedirs` template and the rest to the main
`file_contexts`), so the file contexts are *in* the module and
`semodule -r apse` removes them all. Both `file_contexts.homedirs` entries
are expanded by `genhomedircon` (`HOME_DIR` → `/home/[^/]+/`, `USERID` →
`[0-9]+`, `system_u` → the user's selinux user) into
`file_contexts.homedirs.bin`, which is what `restorecon`/`matchpathcon`
consult for them. `restorecon` (or `chcon -t apse_exec_t`) is what actually
relabels the installed binary — `semodule -i` only registers the contexts.

**Remove:**

```sh
sudo semodule -r apse
```

## Tuning loop

1. Use the system normally (run an app, the broker, the xwayland
   satellite).
2. Harvest denials: `sudo ausearch -m avc -ts recent`.
3. `sudo audit2allow -C <file>` — since the contexts are valid (roles
   associated), this now parses every record and proposes rules; review
   each one and port the ones that make sense into `apse.cil`.
4. Reinstall (`sudo semodule -r apse && sudo semodule -i
   selinux/apse.cil`) and re-run.
