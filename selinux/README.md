# apse SELinux module (phase 8.2)

A local SELinux module that confines the apse stack to its own
domains. The enforcing-mode tuning loop is done (2026-10-29):
audit2allow against a confined run, iterated until a confined
`echo`+`cat`+`ls` produced zero denials — the current rule set is
the loop's output, and any future denials are trimmed the same way
(below). The confined run is verified: types, the `xserver_t` fix,
and the per-instance MCS narrowing all work (a run showed
`apse_t:s0:cN` / `apse_app_t:s0:cN` live — the code writes a
low==high `s0-s0:cN`, which the kernel reports in canonical
single-level form; 2026-10-29).

## The policy is defined directly in CIL

`apse.cil` is the single source of truth — and the install artifact.
There is no `.te`, no `checkmodule`, no build step: on this toolchain
(Fedora 45, policycoreutils 3.11) `semodule -i` accepts CIL directly
(the CIL reader is in libsepol, the library `semodule` links — the
checkpolicy CLI has no CIL input mode; LESSONS #24-25), and the 3.11
module store is CIL-based even for classic `.pp` installs, so the CIL
is the format everything ends up in anyway. Two reasons the old
`.te` → `checkmodule -C` path was dropped:

- **checkmodule -C writes `typetransition` with the raw `.te` class**
  (`file`) and does not normalize it to `process` the way the classic
  checkpolicy pipeline does — the kernel's bprm transition lookup only
  consumes `process`-class avtab entries, so the transition silently
  never fires. Hand-written CIL spells `process` explicitly
  (LESSONS #27).
- the 3.11 module-store CIL dialect has **no `filetrans` keyword**:
  a filename transition is spelled as the *five-field*
  `typetransition` — `(typetransition src tgt class "name" child)`,
  the quoted name distinguishing it from the four-field process
  form. Probed against the reader with a test module; a `filetrans`
  statement fails `semodule -i` with `Unknown keyword` (LESSONS #56).
- a hand-written CIL lets us state the two things the classic
  pipeline gets wrong for a user-spawned type: the **role
  association** (`(roletype unconfined_r apse_t)` — the process
  inherits `unconfined_r` from the shell, and a context is only
  *valid* when the role is associated with the type; without it,
  `setprocattr` of the exec context fails `EINVAL` and the MCS
  narrowing silently degrades, LESSONS #28) and the **`mcs_constrained_type`
  membership** that gives the categories their teeth.

The CIL reader accepts `;` line comments (the libsepol lexer's
comment rule matches `;`; the parser skips to end of line), and
the module uses them; otherwise the file is bare statements.

## What it defines

- `apse_exec_t` — file type for the installed `apse` binary
  (`/usr/local/bin/apse` or `/usr/bin/apse`; the two `(filecon …)`
  statements at the bottom of the CIL, installed in the same command
  as the rules). A *standard application executable*: it carries
  the same attribute set the base policy gives `ssh_exec_t` /
  `useradd_exec_t` / `sudo_exec_t` (`file_type`, `exec_type`,
  `entry_type`, `application_exec_type`, `non_auth_file_type`,
  `non_security_file_type` — see `seinfo -t apse_exec_t -x`), so
  unconfined gets the full file lifecycle on it (including `unlink`
  for updates) by attribute, and the only explicit grant is
  `entrypoint`, which the base policy always gives per-type from
  the defining module (it is required for the
  `unconfined_t → apse_t` transition). No write grant on any of
  those attributes reaches `apse_t`/`apse_app_t`, so a sandboxed
  app still cannot modify the binary.
- `apse_t` — supervisor / S→A→B pipeline / sidecar domain. Reached
  by transition from `unconfined_t` when the binary carries
  `apse_exec_t`. Covers: rootfs mounts (fresh tmpfs / devpts /
  proc, self-bind of `/`, profile binds), the per-instance cgroup,
  the per-instance runtime dir and its sockets (wayland, X, bus,
  broker), the session bus (dbus-broker as `unconfined_dbusd_t` on
  this box), the per-app private state tree (decision #43 — the
  `apse` root dir under `~/.local/state`, created and relabel-walked
  here, bound over the app's home/XDG locations), spawning
  `xdg-dbus-proxy` and Xwayland, the
  namespace/userns/cap setup, and the `/proc/self/exe` re-execs.
- `apse_app_t` — sandboxed-app domain. B execs the app while in
  `apse_t`; the app (and its subprocesses) land here via the
  `bin_t`/`user_home_t`/`gconf_home_t`/`apse_state_t` transition.
  "Confined user app": instance dir, /tmp, /dev nodes, /proc /sys
  /cgroup /etc, home (the private per-app state tree —
  `apse_state_t` — by default, decision #43; the real home dirs with
  `home = "host"`), system libs, session bus, loopback network.
- `apse_state_t` — the per-app state tree
  (`$XDG_STATE_HOME/apse/` — on Fedora `~/.local/state/apse/`), the
  home of decision #43. A dedicated type instead of the
  `gconf_home_t` the gnome module's filecon
  (`HOME_DIR/\.local(/.*)?`) incidentally gives to *all* of
  `~/.local` (everything but `.local/share`). Labeling on this
  kernel: a created inode takes the filetrans result for
  (creator, parent, class) — `filecon` does *not* label created
  inodes (`selinux_determine_inode_label` consults only an mntpoint
  default, a process `create_sid`, or a filetrans) — so the named
  filetrans `(typetransition apse_t gconf_home_t dir "apse"
  apse_state_t)` makes the root the module's type when `apse_t`
  creates it, and the no-rule default of `security_compute_sid`
  (the *parent's* own type) makes everything beneath it inherit:
  one rule labels the whole tree, any depth, on any fs. The range
  takes the parent's low level (`s0`, dominated by every `s0:cN`).
  Because a module type joins no base attribute, the tree's access
  is governed by this module's grants alone: `apse_t` (creation,
  the 0700 chmod, the setxattr relabel walk, and the `mounton` A's
  private-home binds land on), `apse_app_t` (the full file
  lifecycle, incl. fish's `lock`/`watch` and the
  `entrypoint`/`execute` of private-home execs), and `unconfined_t`
  (the user's own inspection, and the test-suite pipeline which
  runs unrelabeled). The one-time migration of a pre-module
  (gconf-labelled) tree and the self-heal of stragglers is S's
  setxattr walk (`prepare_app_state` → `relabel_state_tree`, the
  same mechanism as the `apse_shim_t` relabel; confined mode only).
- `xserver_t` — stock policy transitions `unconfined_t → xserver_t`
  on `xserver_exec_t`, but in confined mode the satellite is
  `apse_t`, so the module adds the `apse_t → xserver_t`
  transition plus `xserver_t` access to the X socket and MIT auth
  file it places in the per-instance dir (precautionary — the Phase
  7.3 e2e logged no denials in unconfined mode; the satellite has
  not yet run in enforcing mode).

**Roles:** both `apse_t` and `apse_app_t` are associated with
`unconfined_r` (the spawner's role, as container-selinux does with
`container_t`/`container_runtime_t`) *and* with `object_r` (so their
file labels are valid). The `unconfined_r` association is load-bearing
— see above.

## Operating modes

**Unconfined mode (default, no action needed).** The binary keeps its
usual label; nothing transitions; the whole stack runs `unconfined_t`
exactly as before, and the module is inert.

**Confined mode.** Relabel the installed binary so the transition
fires:

```sh
sudo restorecon -v /usr/local/bin/apse   # picks up apse_exec_t
```

After that every `apse` subcommand runs as `apse_t`; the
sandboxed app and the helpers it or the pipeline exec run as
`apse_app_t`; Xwayland runs as `xserver_t`. The hard boundary of
the sandbox is still the namespaces + nono landlock/seccomp
(decision #27) — the module is a second, compositable layer.

If an app binary carries a type other than `bin_t`/`user_home_t`/
`gconf_home_t`/`apse_state_t` (check with `ls -lZ <app>`), add a
`(typetransition apse_t TYPE process apse_app_t)` line (plus the
matching process/file allows) to `apse.cil` and reinstall.

## Per-instance MCS (process-level isolation)

In confined mode, each app instance gets its own MCS category
within the user's `s0-s0:c0.c1023` range (a stable FNV-1a hash of
app-id + instance-id). What that category actually isolates is the
**process** level, *not* the object level — the two behave
differently under the live policy's `default_range` rules (LESSONS
#29):

- **Processes are isolated, per-instance.** A `process` takes its
  creator's *full* range (the `process` class has *no*
  `default_range` rule, so `mls_compute_sid` falls through to
  `AVTAB_CHANGE` → `mls_context_cpy`), so every stage of the S→A→B
  pipeline, the app, and the satellites run at that instance's
  `cN`. Both `apse_t` and `apse_app_t` are members of the base
  `mcs_constrained_type` attribute, so the base mlsconstrain
  (`h1 dom h2 or t1 != mcs_constrained_type`) applies: a `cN` subject
  may signal/ptrace/transition only a process whose level it
  dominates, and a *single* category is incomparable with any other
  category — `cN` dominates only `cN`. Cross-instance
  `sigkill`/`sigstop`/`ptrace` are therefore denied (a `cM` process
  is simply not reachable from a `cN` subject). This is *stronger*
  than podman's `cNNN,cMMM` two-category model, where a container's
  level contains a *set* of categories that orders against other
  sets; here one category dominates only itself. One gap: this
  kernel's process class splits `signal` into `signull` (kill 0),
  `sigkill` and `signal`, and the base mlsconstrain constrains all of
  those **except** `signull` — so a kill -0 (used by
  `terminate_app`'s liveness probe) is *not* category-scoped (LESSONS
  #33); it cannot be closed in the module, because libsepol's CIL
  reader rejects `mlsconstrain` in a module CIL.
- **Objects are *not* isolated, per-instance.** A `dir`/`file`/
  `sock_file` created under the user's runtime dir takes the
  *parent's* low level, not the creator's range (`default_range …
  target low` → `mls_context_cpy_low(newcontext, tcontext)`), and the
  parent (`/run/user/<uid>`) is plain `s0`. So the instance dir, the
  build scratch, and every per-instance socket are all `s0`, and any
  `cN` (or `s0`) subject dominates `s0` — every instance and the
  broker may read and write them. There is **no** MCS file/dir
  separation between instances: *content* isolation comes from the
  namespaces + landlock rootfs (each sandbox sees only its own
  instance dir), not from SELinux. The socket and `fd` classes are
  also **not** in the base constrain list, so the broker's session
  sockets and inherited fds keep working across categories.

Mechanics (`src/mcs.rs`):

- at startup, if the process label is `apse_t` (confined) each
  process narrows its own range to the instance's single-level
  `s0:cN` by writing
  `/proc/self/attr/exec` and re-exec'ing `/proc/self/exe` (the
  self-`dyntransition` on `apse_t`). The kernel accepts the write
  only if the target context is *valid* (role associated with type —
  the `unconfined_r` roletypes above) and the new range is a subset
  of the current one (the base `context (contains)` constrain).
  The narrowing happens **before** any binding/creation, so every
  forked child inherits `cN` (a process takes the creator's full
  range); objects created under the `s0` parent stay `s0` (see the
  object-level note above — `default_range … target low`).
- B carries the range into the app exec via setexecfilecon
  (`apse_app_t:s0:cN`); the Xwayland and dbus-proxy satellites
  do the same for their execs.
- the broker (shared by all instances) narrows to *single-level
`s0`* before it binds or creates anything (`mcs::self_reexec_to_s0`,
the same re-exec, run before the listener is taken). The
session-level objects it serves (the `$XDG_RUNTIME_DIR/apse`
session dir and `decision.sock`) are `s0` *by construction* (the
parent's low level, not the creator's range — see the object-level
note), so they are reachable from every category regardless of
who creates them first; no pre-creating is needed. The narrowing
is a *range-hygiene* measure: it keeps the broker's own **subject**
range minimal (a single `s0` level rather than the full spawn range
`s0-s0:c0.c1023`), so a compromised broker cannot act as a
full-range subject or reach another instance's processes (an `s0`
high does not dominate a `cN`).
- SIGHUP re-execs preserve the range (an exec-context write that
  skips any pending explicit context, so the startup narrowing is
  never clobbered).
- a failed exec-context write degrades to a run **without** MCS:
  logged, the run continues. In unconfined mode the mechanism is off
  (labels have no category to carry).

**Session-level objects are always `s0`** (no pre-creating needed):
the session dir `$XDG_RUNTIME_DIR/apse` and `decision.sock` are
created under `/run/user/<uid>` (a `s0` parent), so — by
`default_range … target low` (LESSONS #29) — they take the *parent's*
low level, `s0`, whoever creates them first. There is no
creator-range "pinning" race to win: every instance (`cN`) and the
broker (`s0`) can reach them, because any `cN` dominates plain
`s0`. (An earlier version of this note assumed objects carry the
creator's range and recommended pre-creating the dir at `s0`; that
premise was wrong — the dir is `s0` by construction.)

## Install (needs root)

One command for the rules *and* the file context:

```sh
sudo semodule -i selinux/apse.cil
sudo restorecon -v /usr/local/bin/apse     # confined mode (see above)
```

The CIL carries the two `(filecon …)` statements for the binary
(`system_u:object_r:apse_exec_t:s0` — the MCS category is a
*process* label, never a file label). On 3.11 the store reads file
contexts straight out of the module CIL (libsemanage calls
`cil_filecons_to_string` after `cil_compile` and writes them to the
policy's `file_contexts`), so the file context is *in* the module and
`semodule -r apse` removes it too. `restorecon` (or
`chcon -t apse_exec_t`) is what actually relabels the installed
binary — `semodule -i` only registers the context.

**Remove:**

```sh
sudo semodule -r apse
```

## Tuning loop

1. Use the system normally (run an app, the broker, the xwayland
   satellite).
2. Harvest denials: `sudo ausearch -m avc -ts recent`.
3. `sudo audit2allow -C <file>` — since the contexts are valid
   (roles associated), this now parses every record and proposes
   rules; review each one and port the ones that make sense into
   `apse.cil`.
4. Reinstall (`sudo semodule -r apse && sudo semodule -i
   selinux/apse.cil`) and re-run.
