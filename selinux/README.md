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
  `home = "host"`), system libs, session bus, loopback network, and
  `statfs` on every mounted filesystem type (`filesystem_type` — the
  `df` surface; see the tuning notes below). Its *self*-grants are
  the full base-policy `domain` set, mirrored explicitly (v2.25 —
  the tuning notes explain why the `domain` attribute itself is not
  joined).
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

## Denial-tuning notes (2026-11-12 round)

The grant set above is the output of four user-reported
enforcing-mode tuning rounds (the original one, 2026-10-29; then
`df` + `ls -la /dev` + interactive fish; the `/proc` self links,
`/proc/net`, and the top-level `/proc` entries; and the
attribute-based redesign of that top-level stat) and a fifth
*proactive* completeness pass (v2.25) that re-audited the app's
*self*-grants against the base policy's own `domain` set instead
of waiting for a denial. The shapes the user-reported rounds
added are the ones a future denial is most likely to be:

- **`statfs`/`df` targets the *filesystem*, not the file.** `df`
  (even with an explicit path) stats the root of every mount it
  sees; the `statfs(2)` check runs against the **mounted
  filesystem's** type — the `filesystem` class, the
  `filesystem_type` attribute family (`tmpfs_t`, `device_t`,
  `fs_t`, `proc_t`, `sysfs_t`, `cgroup_t`, …) — never the path's
  label. `getattr` here is superblock metadata (fs type, size,
  free) — no content — so one attribute grant covers every mount
  the app may stat. `df` also stats `/proc/sys/fs/binfmt_misc` to
  detect that mount: `/proc/sys/fs` is its own `sysctl_fs_t` type
  (like `sysctl_kernel_t`/`sysctl_vm_t`), granted `search` +
  `getattr`.
- **`l??????????` = a missing `lnk_file:getattr`.** The
  sandbox's `/dev/ptmx` is a relative symlink in the *fresh*
  tmpfs (decision #39), so it carries the tmpfs default
  `tmpfs_t`, not `ptmx_t`. A listing does two separate checks on
  a symlink: `lnk_file:getattr` (the lstat of the *link itself* —
  what produces the target name) and `lnk_file:read` (the
  readlink). Without the getattr, getdents still knows it is a
  link, so the entry prints `l??????????` with no target. The
  same split applies to *self*-labeled links (the pident links of
  `/proc/<pid>` — #64) and to links whose *target* has a different
  type (`/proc/net` — #65): the readlink is `getattr` + `read`,
  not `read` alone.
- **Per-purpose exec types are not `bin_t`.** Fedora labels most
  of `/usr/bin/*` and `/usr/libexec/*` with per-purpose types
  (`lvm_exec_t`, `iptables_exec_t`, `systemd_systemctl_exec_t`,
  `fsadm_exec_t`, …); a `bin_t` grant reaches only the rest. For
  tools that stat every enumerated entry (fish's completion), the
  target is the **`exec_type` attribute** (the superset of every
  `*_exec_t`): `file:getattr` on the files, `lnk_file:(getattr
  read)` on the symlinks among them.
- **`open` and `read` on a dir are separate.** A tool that maps
  its controlling tty back to a `/dev/pts/<N>` name (fish)
  `opendir`s the (fresh, per-instance) devpts root — `dir:open`
  plus `dir:read` (getdents) — not just `search`. The same
  open/read pair is what the `proc_t`/`sysfs_t`/`sysctl_*`
  enumeration targets need (LESSONS #54, #59).
- **`/proc/<pid>` links are *self*-labeled — the grant is a self
  grant.** The whole `/proc/<pid>/` pident tree carries the
  *target process's own* context (LESSONS #45), so a sandboxed
  app listing its own `/proc/self` hits `apse_app_t:lnk_file` —
  the grant is `apse_app_t` → `apse_app_t` (`getattr` + `read`,
  the split in the bullet above; #64). MCS-bounded in effect: a
  `s0:cN` subject dominates only same-category objects, so it
  cannot reach another instance's pident links. The *top-level*
  self links (`/proc/self`, `/proc/thread-self`, `/proc/mounts`)
  are a different case: the genfs rule labels them `proc_t`, so
  they take `getattr` + `read` on the `proc_t:lnk_file` grant.
- **`/proc/net` is a relative symlink — the link and the content
  are different types.** `/proc/net` → `self/net`: the link is
  `proc_net_t` (genfs), following it lands in the process's
  *own* net directory (self-labeled `apse_app_t`), whose files
  (`dev`, `arp`, …) are `proc_net_t` again — three layers, three
  grants: `lnk_file:(getattr read)` on the link, `dir:(getattr
  open read search)` on the self-labeled directory (covered by
  the existing self grant), and `file:(getattr open read)` on
  `proc_net_t` for the content. Read-only: the content is
  network state (a private netns in the sandbox — loopback only);
  no write is granted.
- **Top-level `/proc` entries are targeted by the base-policy
  attributes, not by type.** Not everything is `proc_t`: the
  `/proc/*` genfs entries carry the **`proc_type`** family
  (`proc_t`, `proc_net_t`, `proc_kcore_t`, `proc_kmsg_t`,
  `proc_mdstat_t`, `proc_psi_t`, `proc_afs_t`, `proc_security_t`,
  `system_map_t`, `proc_numa_t`, …) and the `/proc/sys/*` subtree
  the **`sysctl_type`** family (`sysctl_t`, `sysctl_irq_t`,
  `sysctl_kernel_t`, `sysctl_vm_t`, `sysctl_fs_t`, …) — the same
  two attributes the base policy itself uses for exactly this
  surface (`kern_unconfined` and `container_userns_t` each target
  `proc_type` once, never per type). `ls /proc` stats every entry,
  so the grant is `getattr` per class on each attribute
  (`file`/`dir`/`lnk_file` — the CIL reader takes one class per
  `allow`, LESSONS #67), which covers *current and future* entries
  with no new rule; content access (`open`/`read`) stays per-type
  and deliberately excludes `kcore` (kernel memory) and `kmsg`
  (the kernel log). The one `/proc` type in neither attribute —
  `mtrr_device_t` (`/proc/mtrr`) — keeps a single-rule `getattr`.
- **The app's self-grants are the base policy's own `domain` set,
  mirrored explicitly — `apse_app_t` does *not* join the `domain`
  attribute (v2.25).** A line-by-line audit of `domain.te`'s
  self-grants (the macro expansions, spelled out literal — raw
  CIL has no macros) showed the earlier denial-driven rounds had
  built the mirror incrementally with four holes: `dir` was
  missing `lock`/`ioctl` (`list_dir_perms`) and `watch`
  (`watch_dir_perms`), `lnk_file` was missing `ioctl`, `file` was
  missing `lock`/`ioctl` (`rw_file_perms` — flock on its own
  files, the lockfile pattern), and the fifo grant was the
  non-fips `rw` set while this box has `fips_mode` *on* (which is
  the variant that gives domains `manage_fifo_file_perms`). The
  CIL block is now a complete line-by-line mirror — dir,
  lnk_file, file, fifo (the `manage` superset: mkfifo, open,
  chmod, rename, unlink — a shell's *named*-pipe case on top of
  the anonymous-pipeline `fstat`/read/write one), sem and shm
  (the literal `create_*_perms` expansions — *those classes have
  no `ioctl`*; a `Failed to resolve permission ioctl` from
  `semodule -i` is the detector), process (plus `getcap`),
  `fd:use` (`domain_fd_use`, on) and `key:{link search}`
  (`hide_broken_symptoms`) — with one deliberate omission:
  `fips_mode`'s only non-self rule, `kernel_read_kernel_sysctls`
  (a /proc/sys *content* grant; the /proc design above keeps
  content closed until a denial asks for it). The attribute
  itself was investigated — the `container_t` example: a rootless
  podman process is `domain`-labeled (`s0:cNNN,cMMM`) — and
  rejected (the full audit is the comment block in `apse.cil`).
  The attribute is two-sided; the side that matters is the one
  where `domain` is the *subject*. Joining it would add every
  active `domain → X` rule to the app — 121 of them across 74
  host types (126/76 counting the rules gated by off-tunables):
  `dir`/`file`/`lnk_file` reads across `base_file_type`/
  `base_ro_file_type`/`security_t`/`selinux_config_t`/`var_log_t`
  and the user/man/font/locale families, `context translate`+its
  socket to `setrans_t`, `connectto`+`dbus send_msg` to
  `systemd_resolved_t`, `system module_request` to `kernel_t`
  (`domain_kernel_load_modules` is on), `process {sigchld
  signull}` probes to `init_t`/`sysadm_t`/`unconfined_t`/
  `abrt_*`/`spc_t`/`livecd_t`/`install_t`, and socket-receive
  grants against `unconfined_domain_type`/`netlabel_peer_t`/
  `ipsec_spd_t` (plus `AF_PACKET` against `unlabeled_t`). That is
  the app→host *escape* direction — the exact asymmetry the
  sandbox exists to enforce (the intended direction is the
  reverse: the host user may kill the app, as with a rootless
  podman container, but the app may never reach the host). In the
  *normal* sandbox most of it is gated anyway — the private pidns
  hides host PIDs, the rebuilt rootfs hides host inodes, nono's
  seccomp floor filters the sockets and the `mount`/`AF_PACKET`
  syscalls — which is why `container_t` can be a `domain` member
  without incident: a privileged container *runtime* domain (260
  attributes, incl. `can_load_policy`/`can_setenforce` — the
  svirt orchestrator of a private pidns with mapped uids), not a
  confined application. But apse's primary controls are all built
  by apse itself, in one process tree, and the app runs as its
  *real* uid (no uid mapping, decision #9) — it lacks podman's
  uid-isolation safety net — so the SELinux module is the
  *independent second layer* (defense in depth): pre-emptively
  granting it the full `domain` subject-side reach would disarm
  that backstop the moment a primary control (ns/seccomp) has a
  hole. The *other* side (`X → domain`, 851 active rules, e.g.
  `unconfined_domain_type → domain: process {signal sigkill …}
  file … socket …`) is the host→app direction and is fine by
  design — *not* a reason to reject the attribute (the host user
  managing its own app is the podman model; joining would simply
  broaden our audited `unconfined_t → apse_app_t: process …` line
  into the full surface, within the same-user threat model). (The
  base process neverallows are *not* a blocker either: FSP
  45.24's `domain.te` carries three — `domain → ~domain:process
  {transition dyntransition}` at :59 and two wider ones at
  :116-117 — but the installed policy enforces none of them, since
  the module's own transitions sit squarely in their covered
  directions and have loaded cleanly in enforcing since v2.13 — a
  violation would be refused at `semodule -i` — and joining adds
  none: the module declares no transition from `apse_app_t` as
  subject.) The remaining reason is maintenance: **base drift** —
  a future `domain.te` change (a tunable flip, a new grant) would
  reach the app silently; the explicit mirror is audited in the
  enforcing-mode tuning loop (a denial → a grant). Every
  self-grant is MCS-bounded in effect (a single-level `s0:cN`
  subject dominates only same-category objects).
- **`map` is checked per *protection*, and the only missing case
  was PROT_NONE (v2.25).** `mmap(2)` checks `read`/`write`/
  `execute` against the mapping's prot bits — all already granted
  on the file types the app reaches (document mmaps on the state
  tree already worked: `apse_state_t:file` has `read`+`write`+
  `map`) — so the only untested case was `map` itself (a
  PROT_NONE address-space reservation) on the general file
  families. That is exactly the body of the base's
  `domain_can_mmap_files` tunable (`domain.te`), which is *off* on
  this box (`getsebool` — not the sesearch `:True` annotation, which
  is the condition's polarity) for all 934 `domain` members (even
  `mozilla_t` and `mplayer_t` don't have it) — the grant is scoped
  to `apse_app_t` alone, strictly narrower than the tunable. And
  `map` alone is content-free: a PROT_NONE mapping
  cannot be `mprotect`-ed to a usable prot without the
  corresponding `read`/`write`/`execute` on the target type, which
  stay per-type.
- **Layering: the seccomp floor (decision #25) decides before
  SELinux, and one granted permission is unreachable on this
  kernel (v2.25).** The fifo `manage` set above includes `create`
  (mkfifo) — installed and `sesearch`-verifiable, but the
  *syscall* is auto-rejected by nono's seccomp floor (it is not
  in nono's allowlist) *before* the SELinux check, so in a live
  sandbox it fails EACCES with **zero AVC denials** — a zero-AVC
  EACCES in the sandbox means "seccomp floor", not "SELinux".
  The v2.25 verification therefore ran a purpose-built probe that
  exercises each grant directly (24 checks: getpcaps, a dup'd fd,
  sem/shm lifecycles incl. `SHM_LOCK`, inotify `watch`, `flock`,
  an `O_PATH` `getattr`/readlink, RW and PROT_NONE `mmap`s of
  files, and `ioctl` via a *made-up* command number —
  `security_file_ioctl` fires at syscall entry, at the top of
  `SYSCALL_DEFINE3(ioctl)`, before `do_vfs_ioctl` dispatch and any
  `FMODE_PATH`/command filtering, so it is the only way to
  exercise `ioctl` on a symlink's fd). The other reachability
  fact the mirror documents rather than tests: `lnk_file:lock`
  is granted (the `domain.te` shape) but no unprivileged process
  can ever hit it — the only fd to a symlink is `O_PATH` (a
  final-component `O_NOFOLLOW` open is ELOOP; `open_by_handle_at`
  needs `CAP_DAC_READ_SEARCH`), and every locking path
  (`flock`, `fcntl F_SETLK`/`F_OFD_*`) rejects an `FMODE_PATH` fd
  with EBADF *before* the LSM check.

Not fixed (deliberate, 2026-11-12): the `find /` class — a
whole-filesystem traversal produces thousands of `getattr` on the
root-level dir types and on the per-purpose exec types under
`/usr`. If it is ever wanted it needs a much broader root-dir
surface, not more per-type grants — left as a user decision. The
same deferred class: fish's completion *executing* (not just
stat-ing) the enumerated admin tools (`bootloader_exec_t`,
`mount_exec_t`, `rpm_exec_t`, `lvm_exec_t`, `admin_passwd_exec_t`,
…) — an `execute` denial, a far broader surface than the
read-only `exec_type` grant above — and the metadata sweeps
(`getfattr -R` over `/sys`/`/etc`/`/usr`; a python3 readlink sweep
over `/usr/share/man` — `man_t:lnk_file:read`). Exploration
tools, not sandbox use cases.

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
