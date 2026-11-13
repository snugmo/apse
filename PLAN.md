# apse rework: in-process sandboxing, no containers

## Status

Current: **v2.32** (2026-11-13; enforcing, kernel 7.2.15).
Task 8.8 — the dedicated-type exec world (the `ip`/`hostname`
denial class): the exec grants target the base
**`application_exec_type`** attribute (a refinement of the
original `exec_type` plan — and its name is a trap: it is the
*dedicated* set, 311 compiled members, a strict subset of
`exec_type`'s 1048; what it excludes is exactly the init
scripts, server daemons and inetd services a real-uid app should
never exec — plus the generic catch-alls
`bin_t`/`shell_exec_t`/`usr_t`, which are *not* members and keep
their enumerated rules). Both levels: app side (`apse_t` —
`apse run -- <dedicated-type app>` now works: `hostname`,
`firefox`/`mozilla_exec_t`; the former `xserver_exec_t`/
`apse_exec_t` file rules are absorbed) and child side
(`apse_app_t` — the in-sandbox shell can start the denial
class: `ifconfig_exec_t`, `hostname_exec_t`, `ping_exec_t`,
…). No `noatsecure` at either level: a setuid exec runs
setuid-stripped (secure-exec) — verified: `su` execs but
cannot authenticate (its `unix_chkpwd` helper is equally
stripped), no escalation; `pkexec` (not a member) stays denied.
The app transitions stay **enumerated** — a generic
attribute-object `typetransition` is infeasible (the transition
table is single-valued on (subject, objtype, class), and
`xserver_exec_t`, a member, must keep its own `xserver_t`
target): two were added (`mozilla_exec_t`, `hostname_exec_t`).
The functional wave: `process:setcap` (`ip`'s self-`capset` —
self-only, privilege-neutral) and a `netlink_route_socket`
self-grant (RTNL: this 7.2 kernel's netlink classes carry
separate `nlmsg_read`/`nlmsg_write` permissions and
`getsockname` is the distinct `getattr`; the socket is born in
the creator's context, so the grant is self-targeted and
MCS-bounded). Deliberately left denied: `ping`/`traceroute`-
class raw and ICMP sockets (packet-sniffing in a shared netns —
a separate policy decision, not a tooling convenience),
`netlink_audit_socket` (8.7), and `journalctl`'s journal reads
(the fresh `/run` carries no runtime journal; the persistent one
is host data). `exec_type:file:getattr` *stays* — it is now
*precisely* the stat() path to the `exec_type` remainder outside
`application_exec_type` (the daemon/init trees). The module is
net +4 (297 → 301: 291 allow + 10 typetransition). Underneath:
v2.31 dropped the `home = "host"` profile mode (decision #44 —
the private home is the only mode; the `home` field is a hard
parse error now, the 14 app-side home-family module rules went,
two traversal-only grants went in), on top of v2.30's
per-instance `/etc` files and v2.29's `non_security_file_type`
metadata grants. The broad `file_type:* map` grant (v2.25)
remains dropped: A/B-verified inert on this kernel, `open()`
gates file access (LESSONS #71). The v2.24/2.25 /proc closure
is preserved.

Open: **6.4** (the varlink tier) — parked until a released systemd ships
`PIDs` in scope contexts (re-checked 2026-11-04: v263 still in
development; Fedora 45's 262.1 has no user-bus varlink socket);
**8.6** (a per-invocation `--no-selinux` flag) — the root-only,
persistent file-relabel escape as a CLI knob; **8.7** (in-sandbox
debugging: a boolean-gated `ptrace` grant + `debug` profile/flag) —
gdb/strace inside a confined run. Deferred denial
classes (user's call, accepted — not sandbox use cases): fish's
completion *executing* the enumerated *daemon/init* admin tools
(the v2.32 `application_exec_type` grant covers the dedicated
user-tool types, so only the excluded daemon/init remainder of
the 141 stays denied), the `find /` class,
the metadata sweeps (`getfattr -R`; the python3 man readlink
sweep), and the `ping`/`traceroute` raw/ICMP socket class (a
sniffing capability in a shared netns — a separate policy
decision if it ever becomes a use case).

### Change log (newest first)

- **v2.32** (2026-11-13; enforcing): task 8.8, the dedicated-type
  exec world. *Mechanism:* the exec grants move from
  per-type rules to the base `application_exec_type` attribute —
  the user's refinement of the original `exec_type` plan, after
  checking the compiled membership (`seinfo -a <attr> -x`): 311
  members, a strict subset of `exec_type`'s 1048; the excluded
  737 are init scripts, server daemons, inetd services, **and
  the generic catch-alls** `bin_t`/`shell_exec_t`/`usr_t` (not
  members — the attribute is the *dedicated* set, not "most
  normal binaries"). *Module* (net +4: 297 → 301; 291 allow + 10
  typetransition): (1) `apse_app_t` → `application_exec_type`
  `file` with the full exec union (`entrypoint execute
  execute_no_trans getattr map open read ioctl`); (2) `apse_t` →
  the same union minus `ioctl` — absorbing the former
  `xserver_exec_t`/`apse_exec_t` file rules (both members);
  (3) two new app transitions `apse_t → {mozilla_exec_t,
  hostname_exec_t} process apse_app_t` — the generic
  attribute-object form is infeasible (the transition table is
  single-valued on (subject, objtype, class); `xserver_exec_t`,
  a member, must keep its `xserver_t` target — the Xwayland
  satellite), so the set stays enumerated, one line per
  dedicated-type app actually run; (4) the functional wave:
  `apse_app_t` self `process:setcap` (iproute2's startup
  `capset(2)` — self-only, privilege-neutral: no permitted
  capabilities to gain) and `apse_app_t` self
  `netlink_route_socket (bind create getattr nlmsg_read
  nlmsg_write read write setopt)` — this 7.2 kernel's netlink
  classes carry separate `nlmsg_*` permissions (recvmsg →
  `nlmsg_read`, sendmsg → `nlmsg_write`) and `getsockname` is
  the distinct `getattr`; the socket is born in the creator's
  context (no `sockcreate` filetrans), so self-targeted and
  MCS-bounded. Stays: all `bin_t`/`shell_exec_t`/`usr_t` rules
  (not members), the `exec_type:file:getattr` stat rule (now
  precisely the stat path for the `exec_type` remainder —
  daemon/init trees), the xserver transition and its
  new-process checks, `netlink_audit_socket` (8.7). *Invariant
  documented:* no `noatsecure` at either level — a setuid exec
  runs setuid-stripped (secure-exec): `su` execs but cannot
  authenticate (its `unix_chkpwd` helper is equally stripped),
  `pkexec` (not a member) stays denied, DAC remains the
  backstop. *Verified* (enforcing, zero denials across the
  battery): baseline reproduced pre-change (`route` OK, `ip`/
  `hostname` `file:execute` denied); after — child level: `ip
  link`/`ip addr` (the full RTNL round trip), `hostname` (prints
  the instance's own UTS name), `gpg --version`, `journalctl`
  (executes; its journal reads are a separate host-data
  decision), `su` (execs, stripped, no escalation); app level:
  `apse run -- /usr/bin/hostname` starts (previously "never even
  starts") and the app's `/proc/self/attr/current` shows
  `apse_app_t:s0:cN`; the full suite (231 tests,
  single-threaded) passes. Deferred: `ping`/`traceroute`
  raw/ICMP sockets (a sniffing capability in a shared netns —
  separate policy decision), journal reads. `selinux/README.md`
  documents the grant, the attribute's actual membership, the
  setuid-stripping invariant, and the transition infeasibility
  (LESSONS #76-78).

- **v2.31** (2026-11-13; enforcing): task 8.9, the `home = "host"`
  profile mode is dropped (decision #44): the private home
  (decision #43) is the only mode. *Code:* the profile's `home`
  field is removed — a `home = "…"` line in a user TOML is now a
  hard parse error (`deny_unknown_fields`; the migration signal,
  no built-in profile sets the field, the rewritten profile test
  asserts the rejection). The mode branches are unconditional:
  `prepare_app_state` always runs, the step-1 state-tree carry and
  the step-7 home/XDG binds have no branch (the legacy rw
  self-binds are gone), the `policy.rs` home/XDG Landlock loop
  stays (the same sandbox-side strings resolve to the state-tree
  inodes in B's namespace), and B's pre-exec `chdir` to the
  app's home is unconditional (the warn fallback stays).
  *Module* (net −12: 302 → 290): the 14 app-side home-family
  rules go — the `apse_app_t` dir+file grants on
  `user_home_t` / `cache_home_t` / `config_home_t` /
  `data_home_t` / `gconf_home_t`, the `apse_t → {user_home_t,
  gconf_home_t}` `apse_app_t` typetransitions and their paired
  `process (noatsecure rlimitinh siginh)` mirrors (no process of
  those types can exist in a private-home sandbox); the
  `apse_state_t` grants now carry the app's whole home, incl.
  fish's `lock`/`watch`/`watch_reads` (this kernel's inotify
  check is `watch_reads`, not `watch`), `ioctl` (dash probes the
  script file it is running with TCGETS — a no-op on regular
  files, denied only in the audit sense), the
  `setattr`/`rename` pair (fish's atomic save), and
  `entrypoint`/`execute`/`execute_no_trans`. Two
  traversal-only grants go in: `user_home_t` / `gconf_home_t`
  `dir (getattr search)` — the on-demand shim compiler is
  vforked by S (the `cc` stays `apse_t` under the pinned exec
  context, LESSONS #42), but its `collect2`/`ld` children hit the
  `apse_t → bin_t` transition and run as `apse_app_t` in the
  *host* mount view, probing the real home's `.local`/`.cargo`/
  `src` while linking; traversal-only is safe because the
  in-sandbox app resolves `/home/<user>` to the private tree and
  can never reach those inodes. **Kept, mode-independent:** the
  supervisor-side home rules (profile lookup and traversal, the
  state-tree creation filetrans, the one-time relabel migration
  walk) and the app-side *path-traversal* grants
  (`home_root_t` / `user_home_dir_t` — the bind target still sits
  at the real `/home/<user>` path); the home-family
  `cil_gen_require` lines stay (still referenced, both by the
  supervisor-side rules and the new traversal grants).
  Field-verified enforcing: the probe (a `python3` script in a
  fresh instance) exercises the whole home surface — write,
  `flock`+inotify, atomic save, exec-from-home, path traversal —
  with zero AVCs (a mid-loop `sudo` run against `/root`'s
  `admin_home_t` correctly denied: `apse_t` has no grant there,
  as intended). **Breaking
  change (accepted, personal repo):** a profile TOML with
  `home = "…"` stops parsing — delete the line; an app wanting
  specific *non-home* host paths still has `rw_binds`, while
  home-subtree paths stay unreachable by design (that is the
  isolation).
- **v2.30** (2026-11-13; enforcing): task 8.10, the per-instance
  `/etc` files. `hosts`/`hostname` (constant content: the
  localhost lines + the UTS name on `127.0.0.1` — the loopback
  users expect, not the stock file's `127.0.1.1` alias; the
  `hostname` file = the UTS name) are generated by A into the
  per-instance runtime dir (`$XDG_RUNTIME_DIR/apse/<inst>/etc/` —
  under the /run tmpfs; the scratch was the original location, the
  move to the runtime dir is the user's call) and bound over the
  self-bind-layer `/etc` by the new build step 7.5, so
  `gethostbyname(gethostname())` in the sandbox resolves on
  loopback immediately — no DNS fallback for a nonexistent name,
  no lookup timeouts. Read-only in both modes: the single-file
  binds leave the inodes out of the `/etc` dentry tree, so the
  dir grants do not reach them — Landlock file-level `Read`
  grants (unconfined) and the new `apse_etc_t` (confined: named
  filetrans under `user_tmp_t`, `filesystem:associate` against
  `tmpfs_t`/`fs_t` — `may_create` checks the new label's SID —
  `getattr`+`mounton` on the `net_conf_t`/`hostname_etc_t` bind
  targets). Files are static for the instance's lifetime (an
  in-sandbox `hostname <new>` does not touch them — known
  limitation) and are removed with the runtime dir at teardown;
  the host's `/etc` is never written. Verified unconfined and
  `--network=none` (host `/etc` byte-identical; write attempts
  `EACCES` in both modes — in confined the Landlock floor answers
  before SELinux, so the audit baseline stays flat), confined
  enforcing zero denials, and the integration case
  `etc_files_are_per_instance_and_readonly` (both network
  modes). Deferred spec sub-part: the `--network=none`
  `resolv.conf` extension (none mode's bare netns already fails
  every lookup immediately — no route, no timeout).
- **v2.29** (2026-11-13; enforcing): the module tidy + alignment
  pass (user-driven; every membership and base grant
  seinfo/sesearch-verified against the live policy). Net
  **−10 rules (295 → 285)**: 15 subsumed per-type rules dropped,
  5 attribute-scoped grants added. (1) *Redundancy* — 13
  `apse_app_t` per-type rules whose (type, class, permissions) is
  a strict subset of the v2.27 base-set attribute grants
  (`var_run_t:dir`, `etc_t:dir`+`file`+`lnk_file`,
  `root_t:dir:search`, `bin_t:dir`+`lnk_file`, `usr_t:dir`×2+
  `lnk_file`, `lib_t:dir`+`lnk_file`×2 — all their types are
  members of `base_file_type`/`base_ro_file_type`); then
  `base_file_type:lnk_file` (both base sets ⊆
  `non_security_file_type`) and `exec_type:lnk_file` (all 1048
  `exec_type` members are in the attribute; the identical grant
  rides on it). (2) *`non_security_file_type` metadata grants* —
  the v2.26 `????` thread continued: `dir getattr` (the lstat) +
  `lnk_file { getattr read }` (the readlink), metadata only — no
  `file` class, no `open`/`read` anywhere. The attribute (3205
  members, ⊂ `non_auth_file_type`) excludes the security files
  (`auditd_etc_t`/`auditd_log_t`, the SELinux config/store types,
  `krb5_keytab_t`) and the auth files (`shadow_t`): the ~27
  dedicated /etc config types v2.27 left as `????` clear again,
  and what remains is exactly the set `domain` itself cannot stat
  (audit config + the four shadow entries). (3) *Alignment with
  the base session profiles* (sesearch exact-source on
  `domain`/`guest_usertype`): the cert grants retarget
  `cert_t` → the `cert_type` attribute (8 members — the
  per-service cert stores covered too; the intended widening,
  apps may need to read public keys from the various cert
  stores) and shaped to the base-set profile (dir/file gain
  `ioctl`/`lock`, a new `lnk_file` for the hashed symlink tree
  under /etc/ssl/certs); the bound /dev nodes' `chr_file` grants
  match the base session sets (`urandom` drops `write` — the
  base `domain` grant is read-only; `random` up from stat-only to
  the usertype read set); `user_devpts_t` matches
  `guest_usertype` (append/lock/setattr); `devpts_t:dir` is the
  base guest set `{ ioctl lock read }`, composed with the new
  `filesystem_type:dir { getattr open search }` grant (`devpts_t`
  is a member — it carries getattr/open/search, the direct grant
  the readdir) so fish's /dev/pts enumeration loses nothing; a
  new `file_type:filesystem getattr` (superblock stat of
  file-labelled filesystems — the fresh tmpfs trees, /proc, /sys,
  cgroup2, devpts; the existing `fs_t` rule stays, `fs_t` is not
  a `file_type` member). `exec_type:file:getattr` stays (the
  attribute has no `file` grant; 319 regular files across 140
  per-purpose exec types in `/usr/bin`/`/usr/libexec` stat only
  through it). Live check at the next module reload (the
  installed module is still v2.28).

- **v2.28** (2026-11-13; enforcing): the broad `file_type:* map`
  grant dropped (user's call: too broad as a default position —
  `file_type` is the whole file class, and the only `domain`-side
  precedent in the base policy is the *off* `domain_can_mmap_files`
  tunable). Four rules gone (file/chr_file/blk_file/lnk_file `map`
  on `file_type`); the per-type `map` grants (tmp_t, user_tmp_t,
  the state tree) and the self rule's `map` stay. A/B-verified
  **inert** on this kernel: the identical `mmap(2)` probe on the
  same files behaves the same with the grant present (v2.27) and
  absent, and the run adds zero new denials. That A/B is how the
  investigation found the v2.25 / LESSONS-#68 premise ("mmap is
  checked per protection; the only missing case is PROT_NONE →
  `map`") **does not hold on kernel 7.2.15**: a private PROT_EXEC
  `mmap` of an `etc_t` file by a domain with *neither* `execute`
  nor `map` on the type succeeds with zero AVCs (the vanilla
  7.2.15 source does define a replacement `mmap_file` hook with a
  `FILE__MAP` + per-prot check, but the running 7.2.15-300.fc45
  build does not fire it from the plain `mmap()` path — LESSONS
  #71). Re-confirmed live what *does* gate file access: `open()`
  (`file_permission` read/write) — an `O_RDWR` open of a `usr_t`
  file by a domain without `open` on the type is denied. Practical
  upshot: on this kernel the `map` permission is effectively
  unenforced for ordinary app memory mapping; the revisit trigger
  is a real `map` AVC (a future kernel/Fedora update that wires
  the hook back in is the likely source). The v2.27 base-set read
  grants and the 45-`????` `/etc` state are unaffected; no new
  denials.

- **v2.27** (2026-11-13; enforcing): revision of the v2.26 grant.
  `non_auth_file_type` (3213 members) was judged overly permissive —
  the base `domain` attribute targets *no* `non_auth_file_type` rule
  at all (LESSONS #70's `sesearch -ds` is the tool that proved it:
  `domain`'s literal filesystem targets are `base_file_type` /
  `base_ro_file_type` plus named types; its broad reads come from the
  `files_unconfined_type` *source* side, unconfined-only), and the
  only Fedora rules targeting `non_auth_file_type` are system tools
  (tmpfiles, restorecon). The app's grant is now the `domain`
  baseline file read set as written, on the two base sets only:
  `base_file_type` (23 members) `dir { getattr open search }` +
  `lnk_file { getattr read }`, `base_ro_file_type` (11, all ⊆ the
  former) `dir { ioctl lock read }` + `file { getattr ioctl lock
  open read }`. Read-only, same shape as v2.26. Cost (user's
  least-privilege call, accepted): the dedicated /etc config types
  are members of *neither* base set (`seinfo -x`), so the `????`
  count in `ls -l /etc` goes **4 → 45** — those types, plus
  `hosts` / `hostname` / `machine-id` / `localtime` / `resolv.conf`
  (the five task 8.10 will provide as per-instance binds — the
  substantive fix) and the four `shadow_t` auth files (unchanged:
  `domain` cannot stat them either; `dontaudit`'d, no audit spam).
  Enumerating the ~30 types individually was rejected as the same
  distro-relabel fragility the exec world has (task 8.8). Verified in
  enforcing mode: `ls -l /etc` runs, count 45 as predicted, zero new
  AVC denials; the v2.24/2.25 /proc closure is untouched (the
  `sysctl_*` content types and `proc_net_t` are members of neither
  base set). `apse_t` still has no broad file grant.

- **v2.26** (2026-11-13; enforcing): the `????` fix — a read-only
  grant on `non_auth_file_type` for the app domain. A confined
  `ls -l /etc` showed `d??????????` / `l??????????` for ~42 entries:
  their inodes carry the base policy's *dedicated* config types
  (`auditd_etc_t`, `avahi_conf_t`, `bluetooth_conf_t`,
  `cupsd_etc_t`, `dbusd_etc_t`, `dhcp_etc_t`, `dnsmasq_etc_t`,
  `exports_t`, `firewalld_etc_rw_t`, `ipsec_key_file_t`,
  `kmscon_conf_t`, `lvm_etc_t`, `mcelog_etc_t`, `modules_conf_t`,
  `named_conf_t`, `net_conf_t`, `NetworkManager_etc_t`,
  `openvpn_etc_t`, `pppd_etc_t`, `samba_etc_t`, `sssd_conf_t`,
  `syslog_conf_t`, `system_cron_spool_t`, `tuned_etc_t`, …) — not
  `etc_t` — and none had a rule, so `stat(2)` on each was denied
  (listing itself worked: the /etc dir is `etc_t`). The grant is
  the union of the base `domain` read set — `domain:base_file_type
  dir { getattr open search }` + `lnk_file { getattr read }`,
  `domain:base_ro_file_type dir { ioctl lock read }` + `file
  { getattr ioctl lock open read }` — but targeted at
  `non_auth_file_type` instead of the two base_* sets: the dedicated
  config types are members of *neither* (23 / 11 members, the big
  filesystem types), so the domain rules as written would have fixed
  none of the 42, and enumerating the ~28 types is the same
  distro-relabel fragility the exec world has (task 8.8).
  `non_auth_file_type` = every file type except the auth files
  (3213 members; strictly contains all 23 of `base_file_type`);
  precedent: `hypervvssd_t`'s broad read. Preserved closures,
  verified by a per-type delta over the loaded avtab (`seinfo`
  membership × `sesearch --allow -s apse_app_t`, the four attribute
  targets resolved to their members): `sysctl_kernel_t` /
  `sysctl_net_t` / `sysctl_vm_t` (the /proc/sys *content* types —
  the v2.24/2.25 closure) and `proc_net_t` are **not** members; the
  only /proc-side members are `proc_t` (already fully granted),
  `proc_xen_t` (Xen-only) and `system_map_t` (public symbol maps);
  `tmpfs_t` / `sysfs_t` / `unlabeled_t` are members but already carry
  equal-or-broader grants. New practical surface: the distro long
  tail (config/log/var/spool types — incl. `ipsec_key_file_t`, which
  `user_t` and every `svirt_sandbox_domain` / `container_domain` read
  on the host, i.e. at the sandbox baseline) and the `exec_type`
  members, already `file_type:file map`-able by the app anyway (mmap
  implies read). Read-only by construction: no `write` / `create` /
  `add_name` / `remove_name` / `setattr` / `execute*`. `apse_t` gets
  no such grant (it has none on any /etc type — the supervisor does
  no broad /etc reads; denial-driven). Verification tool: the
  `sesearch -ds` / `-dt` flag pair (match as written, no attribute
  expansion) shows `domain`'s literal filesystem targets are exactly
  `base_file_type` / `base_ro_file_type` plus named types — it does
  *not* target `non_auth_file_type` (LESSONS supplement to #56).
  Verified in enforcing mode: the `????` count went **42 → 4** — the
  four remaining are the auth files (`/etc/shadow`, `/etc/gshadow`
  and the `-` backups; all `shadow_t`), which `non_auth_file_type`
  excludes by definition — and the base `domain` attribute carries
  no stat grant on `shadow_t` either (only the off-gated
  `file_type:map`), so a confined app cannot stat them, exactly
  like any ordinary confined user domain (their denials are
  `dontaudit`'d in base — no audit spam, unchanged). No new
  denials of any kind in the audit log over the run. (Superseded
  the same day in v2.27, above: the attribute was judged overly
  broad and the grant narrowed to the two base sets.)

- **v2.25** (2026-11-12; enforcing): fifth SELinux round — a *proactive*
  completeness pass (no user-reported denial). The app's **self**-grants
  re-derived as an explicit mirror of the base `domain` self-grant set
  (`domain.te` macro expansions, literal CIL — raw CIL has no macros):
  `dir` +`lock`/`ioctl`/`watch`, `lnk_file` +`ioctl`, `file`
  +`lock`/`ioctl` (flock on its own files), the fifo grant → the
  `manage_fifo_file_perms` superset (`fips_mode` is on — the variant
  `domain.te` gives its members; its only *non-self* rule — kernel
  sysctls reads — is the deliberate omission: the /proc content design
  stays closed until a denial asks).
  - `typeattribute apse_app_t domain` investigated and **rejected** (the
    `container_t` example). The attribute is two-sided and the
    *subject*-side matters: joining it adds every active `domain → X`
    rule — 121 of them, 74 host types (126/76 counting rules gated by
    off-tunables) — reads across the base/ro/security/log file families,
    `setrans_t` context translate, resolved `dbus`/`connectto`,
    `kernel_t module_request` (`domain_kernel_load_modules` is on),
    `process` probes on `init_t`/`unconfined_t`/…, and socket-receive
    against `unconfined_domain_type`/`ipsec_spd_t`/`unlabeled_t`
    (+`AF_PACKET`) — the app→host *escape* direction, the exact
    asymmetry the sandbox exists to enforce. The reverse (host→app;
    851 active rules) is *intended*: the host user may signal/kill its
    own app, as with a rootless podman container (verified live, zero
    AVCs — `TERM` is discarded by the pidns-init rule against the
    app's PID-1, `KILL` ends the run) — *not* a reason to reject. The
    base process neverallows are *not* a blocker either (the installed
    policy enforces none of them; the module declares no
    `apse_app_t`-subject transition). The real reasons: apse builds its
    own primary controls in one process tree and the app runs as its
    *real* uid (no podman-style uid-mapping safety net), so the module
    is the *independent second layer* — pre-importing the full
    subject-side reach would disarm that backstop the moment a primary
    control has a hole, and would silently drift with base updates (a
    tunable flip, a new `domain.te` grant); the explicit mirror is
    audited in the enforcing-mode tuning loop (a denial → a grant). The
    full audit is the CIL comment block.
  - Added the one `file_type` grant the denial audit could never
    surface: `map` on `file`/`chr_file`/`blk_file`/`lnk_file` for
    `apse_app_t` alone — `mmap(2)` is checked per *protection* and the
    per-prot perms are all already granted, so only `map` itself (a
    PROT_NONE address-space reservation) was missing. That is the body
    of the `domain_can_mmap_files` tunable, which is *off* on this box
    (getsebool — the sesearch `:True` annotation is the condition's
    polarity, not the value) for all 934 `domain` members; the grant is
    scoped to one type here — strictly narrower than the tunable, and
    content-free (a PROT_NONE mapping cannot be `mprotect`-ed to a
    usable prot without the corresponding read/write/execute on the
    target type).
  - Verified zero-denial in enforcing (a 24-point grant probe in a live
    run; the audit baseline is flat). Two layering findings documented
    rather than denied: `mkfifo` is blocked *before* SELinux by nono's
    seccomp floor (a zero-AVC EACCES in the sandbox means seccomp, not
    SELinux), and `lnk_file:lock` is unreachable on this kernel (the
    only fd to a symlink is `O_PATH`; flock rejects it before the LSM).
- **v2.24** (2026-11-12): the per-type `/proc` stat grants of v2.23
  replaced by the two base attributes that define exactly that surface
  — `proc_type` (the `/proc/*` genfs family) and `sysctl_type` (the
  `/proc/sys/*` subtree family): `getattr` per class per attribute
  (`file`/`dir`/`lnk_file` — one rule per class; the module store's CIL
  reader rejects a multi-class `allow`, LESSONS #67). `getattr` is a
  content-free stat (26 types covered, was 7); content access
  (`open`/`read`) stays per-type (`proc_t`/`proc_net_t`/
  `sysctl_kernel_t`/`sysctl_vm_overcommit_t`/`sysctl_fs_t`/
  `sysctl_crypto_t`), still excluding `kcore` (kernel memory) and `kmsg`
  (kernel log); `mtrr_device_t` (in neither attribute) keeps a single
  rule. The alternative shape (joining a *domain* attribute, e.g.
  `unpriv_userdomain`) investigated and rejected: attribute
  *membership* would subject `apse_app_t` to every base rule targeting
  that attribute, including neverallows (attribute *targeting* is the
  low-risk direction the base policy itself uses). Verified zero-denial
  (module 27→28; sandboxed `ls /proc`, `ls -la /proc/self`, the
  `/proc/net` probes).
- **v2.23** (2026-11-12): user-reported `/proc` listing denials from the
  sandbox. (a) The pident links (`cwd`/`exe`/`root`) are *self*-labeled
  `apse_app_t:lnk_file` (the `/proc/<pid>/` tree carries the *target
  process's own* context, LESSONS #45) — the self grant grew to
  `(getattr read)`. (b) The *top-level* self links (`/proc/self`,
  `/proc/thread-self`, `/proc/mounts`) are `proc_t` — `getattr` on the
  existing `lnk_file` grant; `/proc/net` is a *relative* symlink
  (`proc_net_t`) — content needs `file:(getattr open read)` +
  `dir:(getattr open read search)` on `proc_net_t` (read-only: private
  netns, loopback only). (c) `ls /proc` stats every top-level entry —
  per-type `getattr` only, no content; deliberately no `open`/`read` on
  `kcore`/`kmsg`. Verified (sandboxed `ls -laZ /proc/self/`, `ls -la
  /proc`, `stat`/`head` on `/proc/net/dev`, a pty-driven fish
  `cd /proc` + `cat`).
- **v2.22** (2026-11-12): denial classes from a confined `df`,
  `ls -la /dev`, and interactive fish. (a) `df` `statfs`es the root of
  every mount — the check targets the **mounted filesystem's** type
  (`filesystem` class, `filesystem_type` attribute family) — one
  `filesystem:getattr` grant covers every stat-able mount, plus a
  `sysctl_fs_t` grant for df's binfmt_misc detection. (b) `/dev/ptmx`
  is a fresh-tmpfs symlink (decision #39) — the lstat of the link
  (`lnk_file:getattr`) is separate from the readlink
  (`lnk_file:read`). (c) fish's completion stats every `/usr/bin`
  entry — Fedora labels them per-purpose `*_exec_t` — so the grant is
  on the **`exec_type` attribute** (the superset of every `*_exec_t`):
  `file:getattr`, and on the symlinks among them `lnk_file:(getattr
  read)`. (d) fish maps its controlling tty back to a `/dev/pts/<N>`
  name by enumerating the per-instance devpts root: `dir:open` + `read`
  (the opendir/getdents split, LESSONS #54/#59), not just `search`.
  Verified (a pty-driven interactive fish with completions; the audit
  baseline is flat).
- **v2.21** (2026-11-12): decision #43's SELinux side refined: the
  per-app state tree gets a dedicated `apse_state_t` instead of riding
  the `gconf_home_t` the gnome module's `HOME_DIR/\.local(/.*)?` filecon
  incidentally gives to *all* of `~/.local` (on this kernel `filecon`
  does not label created inodes — a named filetrans, spelled as the
  five-field `typetransition` in this module store's CIL dialect, makes
  the `apse` root `apse_state_t` at creation; the no-rule default makes
  the subtree inherit; S's setxattr walk migrates a pre-module tree).
  Closed the user-reported `ps` denials inside a sandboxed foot: `open`
  (opendir) atop `read` (getdents) on the `proc_t`/`sysfs_t`/
  `sysctl_kernel_t` dirs, a self-referential `dir:ioctl` on ps's own
  `/proc/<pid>` dir, `bin_t:dir open` for fish's completion
  enumeration. Completes the v2.20 open item: the confined-mode field
  verification of the private home.
- **v2.20** (2026-11-11): decision #43 landed: the default profile no
  longer rw self-binds the real `$HOME` and XDG dirs — the app's home
  is a **private per-app state tree** under
  `$XDG_STATE_HOME/apse/<app-id>/` (home/config/cache/data/state
  subdirs) bound over `$HOME` and the XDG locations — the container-era
  per-app home volume (persistent, disconnected from the real home and
  the host desktop), re-implemented as binds. The app's environment is
  unchanged (the redirect is invisible); `home = "host"` restores the
  pre-8.3 behaviour; the profile's `rw_binds` layer on top in both
  modes. Per-app, not per-instance (the instance's ephemera stay in the
  per-instance runtime dir). The SELinux module followed (the tree is
  `gconf_home_t`: S's create grants, the app's `entrypoint`/`execute`
  on its files, the `apse_t → apse_app_t` fallback transition).
  Verified in the test suite (a `$HOME` write lands in the state tree,
  never the real home; a hermeticity marker; a private-home write to
  the Landlock probe).
- **v2.19** (2026-11-04): the 6.5.5 `serve`-label drag refinement is
  done: the relay tracks the client's active drag source (a
  `start_drag` until that source's `cancelled`/`dnd_finished`/`destroy`;
  a `dnd_drop_performed` does *not* end it — a "move" drop transfers its
  data on the drop), so the `send` (serve) records on that source are
  labeled `selection=drag` instead of the shared `clipboard` (a
  `wl_data_source` is shared by the clipboard and the drag, and the
  wire does not say which); the adjacent `read` on the stable-protocol
  offer stays `selection=clipboard` — the exact contrast the
  refinement exists to make. Verified end to end and at unit level.
- **v2.18** (2026-11-04): the `dbus-proxy`/`xwayland` satellites and
  the broker are now **field-verified in confined mode** (enforcing,
  kernel 7.2.15; LESSONS #45–#46). The `xwayland` satellite boots
  Xwayland to a full session (`xserver_t:s0:cN`) — real X clients
  through the per-instance socket, clean TERM→KILL teardown, zero
  denials. Closing it exposed the shape of a satellite's confined exec
  (LESSONS #46): the exec-time cred hooks check
  `noatsecure`/`rlimitinh`/`siginh` against the *new* SID, and their
  denial is a *silent degradation* (a soft-rlimit reset, an itimer
  clear), never an abort — only the asymmetric `xserver_t` leg needed
  the triple. The real blockers were the inherited fds (checked against
  the *creator's* type; a missing `accept` masquerades as a backlog
  spin) and the satellite's teardown signals on the transition rule;
  the X `-auth` lifecycle needed create/append/write, not just read.
  The `dbus-proxy` sidecar gained a stale-socket probe; the broker was
  re-verified after the kernel upgrade (the LESSONS #45 premise held on
  7.2.15: `comm_write` is byte-identical).
- **v2.17** (2026-11-03): the decision-#42 `PR_SET_PDEATHSIG` cascade is
  **field-verified on both legs** (LESSONS #44) — decision #42 is
  complete in confined mode. SIGKILL S → the belt delivers USR1 to A,
  whose handler kills B; SIGKILL A → the belt delivers USR1 into B's
  pidns (the strace marker `si_code=SI_USER`, `si_pid=0` — a
  kernel-internal delivery, invisible to audit; strace is the only
  window). The `AppKillGuard` sweep ends the run with no process
  alive. The confined-mode completion of #42 landed in this pass too:
  `ensure_shim` relabels the `.so` to the dedicated `apse_shim_t`
  (LESSONS #41) and compiles it under a *pinned* exec context (LESSONS
  #42); the 7.2.11 correction (the exec clear is an *unconditional* SID
  change, not the `secureexec` path) is baked into the module's docs.
  Also in this pass: the sandbox's `/dev` build now creates a fresh
  private `/dev/shm` (a fresh tmpfs, mode 1777) — an app mapping a shm
  file (the `wl_shm` path) previously hit `ENOENT`. Open (not
  load-bearing while the guard exists): B *survived* the belt's USR1 in
  the field test (it resumed via `restart_syscall` — an `SA_RESTART`
  action is suspected from the Rust ELF/dynamic-linker startup).
- **v2.16** (2026-11-02): decision #42 — a kernel-level
  `PR_SET_PDEATHSIG` cascade closes the S-death boundary #41's
  `AppKillGuard` cannot cover (a default-terminate signal to S itself —
  the actual run-#1 shape): A arms `pdeathsig = SIGUSR1` (not
  `SIGTERM` — a pdeathsig that lands in a block stays *pending*
  forever) with a handler installed after the second fork (so B does
  not inherit it) that sets a flag; the delivery `EINTR`s A's blocking
  wait, `waitpid_retry` reports it, and A kills B (`SIGKILL`) and exits
  137. B re-arms its own link (7.2 `fork` *resets* pdeathsig — it is
  not inherited) and, in confined mode, an `LD_PRELOAD` shim re-arms it
  across the exec that may clear it. The shared `apse::pdeathsig`
  module (`set`/`get`/`ensure_shim`) serves both the run pipeline
  (`SIGUSR1`) and the `xwayland` satellite (`SIGTERM`; signal-suffixed
  shim names). Verified at unit level against `~/src/linux` (the 7.2.11
  `PR_GET_PDEATHSIG` arg2-pointer and `fork`-reset semantics).
- **v2.15** (2026-10-30): decision #41, LESSONS #37 — a run can no
  longer orphan the app's namespace when the pipeline dies. Run #1: S
  died silently mid-run (no core, no journal, no error line), A died
  shortly after, and the app's pidns (B is its PID 1, #13) ran on
  forever; the only trace was the sub-cgroup `rmdir` failing
  `ENOTEMPTY`. Both code-level holes closed: (a) `EINTR` was fatal in
  both reapers' blocking `waitpid`s — `waitpid_retry` loops on it in
  both (a reaper that must live must never die on an interrupt);
  (b) the new `AppKillGuard` (armed at handoff, dropped at the run's
  end) SIGKILLs whatever is still in the instance sub-cgroup — it does
  *not* rely on the kernel's zap of a dying pidns init (#14). Field-
  verified by SIGKILLing A: the old code reproduced the orphan, the new
  code left nothing.
- **v2.14** (2026-10-30): the full chain is verified with a *real GUI
  app under enforcing mode*: `foot` rendered through the `--proxy`
  relay into live sway, with **zero denials** across the whole
  boot+render cycle (the relay `apse_t:s0:cN`, the S→A→B pipeline, the
  app `apse_app_t`, including every SCM_RIGHTS fd exchange). The
  enforcing-mode tuning closed five classes of gap (decisions #39–#40;
  LESSONS #34–#36): devpts without `MS_NODEV` (a VFS gate decided
  before any LSM, never audit-logged); the `run` teardown sparing live
  sidecar sockets (the relay's `--listen` path outlives every `run`);
  the relay's *receive-side* grants (a dropped fd is silent — only
  `MSG_CTRUNC` flags it); the fresh-tmpfs symlink label trap
  (`/dev/ptmx` is `tmpfs_t`, not `ptmx_t`); and the `dir`
  `open`/`read` distinction (fontconfig `open()`s before it
  `getdents()`s).
- **v2.13** (2026-10-29): Phase 8.2 done — the SELinux module is
  installed and tuning-looped: written directly in CIL
  (`selinux/apse.cil` is the single source of truth and the install
  artifact — `sudo semodule -i`, no `.te`/checkmodule/build step); a
  confined `echo`+`cat`+`ls` produced zero denials across nine
  consecutive runs. A follow-up `default_range` investigation corrected
  the MCS semantics (LESSONS #29): the per-instance `cN` isolates the
  instance's **processes** (a `cN` subject may only signal/ptrace/
  transition a same-`cN` process — *stronger* than podman's
  `cNNN,cMMM`), **not** its **objects** (a `dir`/`file`/`sock_file`
  created under the `s0` runtime parent takes the parent's low level
  `s0`) — file-level separation is the namespaces + landlock rootfs.
  The same pass found the `signull` (kill -0) gap (not in the base
  mlsconstrain, unfixable in a module CIL — LESSONS #33). 8.4 (the
  integration test suite) and 8.5 (the threat-model review) are done
  (2026-10-24); the full chain verified at probe level (a sandboxed
  `wayland-info` driven through the `--proxy` relay into the live
  sway).
- **v2.12** (2026-10-24): Phase 7.3 done — `apse xwayland`, the
  host-side per-instance Xwayland satellite (sway's spawn pattern:
  sidecar-created+listened `-listenfd` socket in the per-instance
  runtime dir, `-displayfd` readiness gate with display-number
  cross-check, `-auth`, `-nolisten tcp`, `-rootless`). Verified
  end-to-end (a real X11 client connects to the instance socket) and on
  both teardown paths (SIGTERM; SIGKILL with the pdeathsig restore shim
  — decision #37).
- **v2.11** (2026-10-24): Phase 7.2 done — `apse dbus-proxy`, the
  host-side per-instance `xdg-dbus-proxy` sidecar (direct spawn, not a
  unit; public `bus.sock` in the per-instance runtime dir, owner-only;
  see/talk/own/call/broadcast rules forwarded verbatim, fail-closed
  once any is present). The child's lifetime is a *fd*: a private
  socketpair handed over as `--fd=3` (non-CLOEXEC — `execve` closes
  CLOEXEC fds), so even a SIGKILL'd sidecar tears the proxy down
  (decision #36); verified pass-through + SIGTERM + SIGKILL teardown.
- **v2.10** (2026-10-24): the in-process architecture docs (8.1): the
  S→A→B pipeline, the rebuilt rootfs, the nono policy, the
  relay/broker/decider, the layered-containment table, install/
  profiles/the per-app relay recipe, verify-your-setup, and the
  residual-risk list; the zbus 6 migration (`6725560`) landed with it.
  Phase 5.5 done: Firefox ran through the full S→A→B pipeline — the
  window reached the compositor, network egress worked, and a SIGTERM
  tore it down cleanly; it also confirmed decision #32 (the supervisor
  services *every* trapped notification, so multi-process apps that
  inherit the filter don't deadlock). The code-quality sweep:
  rustfmt/clippy/check clean, the dead `security_context.rs` module
  removed, the broker's public API tightened, the container-era
  fixtures/Mode-A-B/quadlet comments purged, and the unsafe surface
  audited (all ownership transfers and the one `transmute` are
  SAFETY-documented; 192 tests green).

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
| `/dev` | fresh tmpfs + **bind-mount** of the host nodes `null`, `zero`, `full`, `urandom`, `random`, `tty`; `/dev/ptmx` is a **symlink** into the fresh `devpts` instance (a host bind would hand the app the host's pty master); a fresh private `/dev/shm` tmpfs (mode 1777 — the `wl_shm` path) | bind-mount, not mknod: the nodes keep their canonical genfs SELinux labels (`null_t`, `urandom_t`, …), so the confined domains need plain standard `open/read/write` rules (matches rootless-runc). Clear error if a host node is missing. |
| `/dev/pts` | `mount devpts -o newinstance` | fresh instance, isolated from host pts |
| `/dev/dri` | bind from host | GPU; user must be in `render` group (same requirement as rootless podman); `--no-gpu` skips |
| `/proc` | fresh procfs mount | allowed in an unprivileged user ns (namespaced view); verify on target kernel (Phase 2) |
| `/sys` | fresh tmpfs + binds of `devices/`, `class/` (ro unattainable — #21) | only the sysfs *mount root* is unbindable (#18); these subpaths cover DRM/PCI discovery |
| `/run` | fresh tmpfs | per-instance dir (tagged wayland socket, supervisor socket, (later) the dbus-proxy socket, (optionally) ssh-agent): its *content* is the host's per-instance runtime dir, **carried into the step-1 scratch before this mask** and bound in from there — binding the host path directly would silently hit this fresh tmpfs's own empty stand-in dir (#28) |
| `/tmp` | fresh tmpfs | `size=` from profile |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc` | ro-binds | `/etc` as-is; passwd/group map consistently through the uid/gid maps |
| `/etc/hosts`, `/etc/hostname` | single-file `MS_BIND` from the per-instance runtime dir (`<runtime-dir>/etc/`, new step 7.5 between the home binds and the `/var` mask) | task 8.10: the generated files carry the UTS name `apse-<app>-<inst>` (`127.0.0.1`), so it resolves on loopback from `files` with no DNS fallback. A single-file bind does not put the inode under the `/etc` dentry tree, so the `/etc` *dir* grants do not reach it: the file-level Landlock grants (`Read`) and `apse_etc_t` (read-only) mediate. The targets must exist on the host — a user-owned build cannot create files in the root-owned `/etc`. The sources are static for the instance's lifetime and are removed with the runtime dir on teardown |
| app dir | ro-bind (e.g. `/opt/rustrover`) | path from the app profile |
| app home and XDG dirs | binds of the per-app state tree over the standard locations | **decision #43** (decision #44: the private home is the only mode): a **private per-app** tree at `$XDG_STATE_HOME/apse/<app-id>/` bound over `$HOME` and the XDG locations (the container-era per-app home volume, re-implemented as binds; carried into the step-1 scratch before the home is replaced — #28's trap; binds go home → config → cache → data → **state last**; the app's env is unchanged — the redirect is invisible; B `chdir`s to the app's home before the exec). The profile's `rw_binds` layer on top. |
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
`~/.config/apse/apps/<app-id>.toml` (ro binds, rw binds, masked
paths, env vars, network mode, gpu, tmp size). The app's home is
always the private per-app state tree (decisions #43/#44). New
deps: `nono` (pinned), `toml`, `serde`, and `zbus` (Phase 6, D-Bus
tier).

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
| 26 | Deterministic handoff: the verdict pipe | B blocks on an A→B verdict pipe before exec (`1` = exec, `0` = exit 126 — never an unsupervised exec): the seccomp listener is allocated `O_CLOEXEC` by the kernel, and `pidfd_getfd` on B succeeds only while B is still dumpable — *pre*-exec; if B started execing while A was still extracting, the loader's `openat`s would pile up on the dying listener, and `seccomp_notify_free` completes every pending notification with `-ENOSYS` (observed: `Error 38` on `libtinfo.so.6`). A sends the verdict only after the extract + `SCM_RIGHTS` to S have completed. Two close-order invariants: B *inherits* the verdict read end (A closes its copy only *after* the second fork — closing it before the fork left B polling a dangling fd number), and A ignores `SIGPIPE` after the fork (a failure-path verdict can hit a pipe whose reader is already gone and must not kill A before it reaps B). |
| 27 | nono's three-stage prepare/apply — the filter must never precede landlock's *prepare* | nono's `apply_landlock` calls `open_path_rule` → `open(O_PATH)` for every rule path. Installing the seccomp-notify filter *first* traps those opens: B blocks in a notification wait with no supervisor running yet — a hard deadlock (observed: 300 s timeout, zero output). The working order is nono's own prepare/apply split: `prepare_landlock_with_abi` (opens all rule paths, while unfiltered) → install the combined filter → `apply_raw` (consumes the prepared fds; opens nothing). #22's "the filter must precede landlock" survives as *the filter must precede landlock's **apply***. |
| 28 | The rootfs scratch lives on `/var/tmp`; the runtime dir is carried before the `/run` mask | The scratch must stay resolvable through every build step, so it cannot sit under any masked tree. The old location (inside the per-instance runtime dir) is under `/run` for the default `XDG_RUNTIME_DIR=/run/user/<uid>` — and a bind *source* resolved after the fresh-`/run` mask hits the fresh tmpfs's empty stand-in directory: a **silent self-bind no-op** that never crosses to the host (writes "succeed" into the throwaway tmpfs; the app-side socket is invisible). New layout: the scratch is `/var/tmp/.apse/<inst>` (mode 0700, hidden by the `/var` mask *and* the Landlock floor), and the per-instance runtime dir is carried into it in step 1 — the only point where its host path is still resolvable — then bound onto the fresh `/run`'s instance dir in step 5. S removes the scratch (and its parent) on exit. |
| 29 | Raw pidfd syscalls: explicit zero flags; the *host* pid is the right argument | `libc` 0.2 (gnu x86_64) exposes `SYS_pidfd_open`/`SYS_pidfd_getfd` as numbers only, so they are called via `syscall(2)`. The kernel does `if (flags) return -EINVAL` for both, and a short `syscall(2)` call leaves the flags register uninitialised → spurious `EINVAL` (observed on `pidfd_open`). Pass `0` explicitly. Also, `pidfd_open` resolves the pid *globally* (`find_get_pid` → `find_vpid`, the init-namespace hash), so A — inside the fresh pidns — must pass B's **host** pid, which is exactly what `fork()` returns (`clone` returns `pid_vnr` = `level[0].nr`, never the caller-namespace-local pid; B's local pid `1` would be the wrong argument). |
| 30 | The selinuxfs attr strings are NUL-terminated, and `trim` will not strip that | The MCS self-narrowing re-exec guard compared the read-back `/proc/self/attr/current` range to its target with `str::trim` — which does not strip the NUL the kernel appends — so the guard never matched and apse re-execed itself ~260k times. Fix: truncate at the first NUL before parsing (`mcs::parse_label`), and write the guard's target in the single-level form `mls_sid_to_context` returns (a low==high range collapses on read-back; LESSONS #30). |
| 31 | Open `/proc/self/attr/exec` without `O_CREAT` | `std::fs::write` opens `O_CREAT\|O_TRUNC`; on a freshly mounted in-sandbox procfs that first open races a negative dentry and runs `may_o_create` — SELinux answers with an `add_name` denial on the `attr/` directory. Non-fatal (the kernel clears the flag and the open succeeds) but it logs a denial every run, and granting the full chain does *not* fix it (the open then proceeds to an `i_op->create` the procfs attr dir has no handler for → `-EACCES`). The fix is `OpenOptions::write(true).truncate(true)` — the file always exists, so no creation is asked for (LESSONS #31). |
| 32 | The supervisor services *every* trapped notification, with no pid filter | `handle_notif` dispatches by syscall number only: the seccomp filter is inherited by the app's children, so the supervisor must service *every* trapped notification with the same capability set — a pid filter deadlocks multi-process apps (a child's notification is never answered). A failed verdict answers `EPERM`, never hangs. Confirmed by the Phase-5.5 Firefox e2e (a real multi-process GUI app to a clean SIGTERM shutdown). |
| 33 | Signal semantics are mode-dependent (merge reconciliation) | `run` forwards SIGHUP to the app and exits **129** (there is no in-place rebuild of a live sandbox); the `wayland` modes treat SIGHUP as a *rebuild* (in-place re-exec in `--listen` mode, clean exit for a systemd restart when socket-activated). SIGTERM/SIGINT are always forwarded to the app (SIGKILL after 2 s — the pidns-init ignores default-action signals, #13). S sends `READY=1` to systemd after the handoff and untags the Wayland socket on teardown. |
| 34 | Varlink first, D-Bus as fallback | (Superseded by #35.) `apse run` starts the scope via **Varlink** `io.systemd.Unit.StartTransient` on the *user* manager socket (`/run/user/<uid>/systemd/io.systemd.Manager`) — JSON over a unix socket, one request/response, no polkit, hand-rolled (~60 lines, no dep on the primary path). Requires **systemd ≥ 261** (`StartTransient` from commit 913b81735e; the `io.systemd.Unit`/`io.systemd.Manager` skeletons from 258); distro coverage (pkgs.org, 2026-10): Ubuntu 26.10, Fedora 45+, Arch, Tumbleweed, Wolfi. Older stacks (Debian 13, Ubuntu 26.04 LTS, RHEL/EPEL) fall back to **D-Bus** `org.freedesktop.systemd1.Manager.StartTransientUnit` on the session bus (`zbus` — chosen over `dbus` 0.9: zbus is the maintained, stable, widely-used crate). Tier order at runtime: varlink → D-Bus → raw-cgroup; the outcome is logged. |
| 35 | D-Bus primary, varlink deferred (supersedes #34) | Hands-on verification on the Fedora 45 target (systemd 261) overturned the varlink-first plan. (a) `io.systemd.Unit.StartTransient` is **service-only**: a scope created without PIDs **refuses to start**, and a scope context with `PIDs` landed on `main` only after v262 (abde7e80d0, 2026-10-16) — no *released* systemd can do the operation via varlink (that is why 6.4 is parked). (b) D-Bus `StartTransientUnit` works on every user-systemd stack (scopes since v252; no polkit on the session bus): unit `*.scope`, mode `replace`, `{ PIDs: <au> [self] }` (array of uint32; reply type `(o)`, not `(uo)`). (c) `StopWhenUnneeded=true` is **harmful** on v261 scopes (verified: stopped immediately, member alive) and is not needed anyway — a scope auto-stops and is removed **recursively** when its last member leaves. (d) `Delegate=` is unnecessary (the user-session cgroup subtree is **user-owned**); the manager also lands transient scopes in `app.slice` — the instance sub-cgroup's parent is read from `/proc/self/cgroup` after the call, never assumed. D-Bus (`zbus`, `src/systemd.rs` — driven on a fresh local tokio runtime per call; the process-global one is dead in a forked child) is the primary tier for all distros; varlink is a future tier (6.4); the raw-cgroup path remains the last resort. |

| 36 | The D-Bus sidecar's lifetime is a *fd*, and that fd must be *non*-CLOEXEC | `apse dbus-proxy` owns an `xdg-dbus-proxy` child (signalfd + pidfd `poll(2)`) and hands the proxy one end of a private **socketpair** as `--fd=3`. The fd must reach the child **without** CLOEXEC: `execve(2)` *closes* CLOEXEC descriptors (the inverse of the usual "protect the fd" reflex) — `pre_exec` dups the end onto 3, *clears* the flag, and closes the original. The proxy writes one `x` byte on startup (the sidecar's readiness gate) and exits when its fd sees the peer close — so even a SIGKILL'd sidecar tears the proxy down. Socketpair, not pipe: the installed GLib 2.90 does **not** fire that watch on pipe EOF, but does on a socket peer close (the same thing flatpak passes), and it masks `G_IO_ERR\|G_IO_HUP\|G_IO_NVAL` out of the events it hands `ppoll(2)` (an IRIX-era workaround) — so the watch fires on the kernel's unrequested `POLLHUP` (verified with an `LD_PRELOAD` ppoll tracer). `pre_exec` also resets the child's signal mask (a proxy orphaned with every signal blocked would be killable only by SIGKILL). The long Phase-7.2 bug: a rewrite dropped `--fd=3` from the *argv* — the proxy never wrote the sync byte, the sidecar parked forever in its readiness `read`, and the child outlived the sidecar (exposed by a gdb ppoll-array dump vs a shimmed control run). |
| 37 | Xwayland runs *host-side*, not inside the sandbox; the satellite owns a bound socket and a chosen display number | `apse xwayland` (7.3) gives a sandboxed app an X server by running Xwayland on the host as an ordinary Wayland *client* of the compositor, sharing only its X socket into the sandbox through the per-instance runtime dir. The in-sandbox alternative was rejected: the X server is the least-trusted component of the X stack (it can read every client's pixels and inject input) — a host-side satellite is the same documented trust tier as the dbus sidecar and the relay, not a new hole — and the private rootfs would need the entire X/GL stack for a rarely-used feature. The spawn mirrors sway's own: the sidecar creates and binds the socket itself (`-listenfd`, non-CLOEXEC — the #36 fd contract) and **must `listen(2)` it before the handoff** (Xwayland's `SocketReopen` adopts the fd *as-is* and never listens — an unlistened fd makes `accept(2)` fail `EINVAL` on every poll wake: a 100%-CPU hot spin; sway's spawn listens first). `-displayfd` is the readiness gate (the display number in use is written when Xwayland can take clients; a mismatch against `--display` is a hard error — it does not renumber, so the profile must name a stable display); `-rootless` by default, `-nolisten tcp` always. The originally-planned `-once` was XDMCP *session* semantics (a no-op for a non-XDMCP rootless Xwayland, which does **not** exit when its last X client disconnects) — dropped. The lifetime backstop for a SIGKILL'd satellite is the #42 `PR_SET_PDEATHSIG` belt — the `xserver_t` exec *clears* pdeathsig (a security-credential change), so it must be *re-armed inside the child* by an on-demand-compiled `LD_PRELOAD` shim (the full mechanism: #42). Given `-listenfd`, Xwayland does **not** create the conventional `/tmp/.X11-unix/X<N>` — the instance socket is the *only* host-visible X path. |
| 38 | A custom SELinux module, or reuse of container-selinux? | **The module stays custom** — `apse_t` + `apse_app_t` (+ the `xserver_t` fix, later `apse_shim_t`), defined directly in CIL: `selinux/apse.cil` is the policy source *and* the install artifact (`sudo semodule -i`, one command for rules *and* file contexts; LESSONS #24-28). Reusing podman's types was rejected (2026-10-28, amended): it would leave the app in the more-privileged `container_runtime_t` domain, the label is third-party owned, and losing it degrades silently. **Per-instance MCS categories** (`src/mcs.rs`): one `cN` per (app-id, instance-id) via a stable FNV-1a hash; every confined apse process self-narrows via a `dyntransition` re-exec before creating or binding anything; B and the satellites carry the range into their execs; the broker narrows to single-level `s0`. The category isolates the instance's *processes* (the base mlsconstrain), not its *objects* (created objects are `s0` — file separation is the namespaces + landlock rootfs; LESSONS #29/#33). Details: `selinux/README.md` (the "Per-instance MCS" section). |
| 39 | devpts must not be mounted `MS_NODEV` | The VFS `may_open_dev` (`fs/namei.c`) denies `open(2)` of **device files underneath an `MNT_NODEV` mount** (or a superblock with `SB_I_NODEV`) — an EACCES decided in the open-path permission check, *before* any LSM hook, and *never* audit-logged. Effect: the app could never open `/dev/pts/ptmx` (or any allocated pty slave) — every pty consumer in the sandbox failed at the first `open(2)` with EACCES regardless of DAC (0666), Landlock, or SELinux. A pure VFS gate on *device* files only, so it masquerades as a MAC problem (the pts *directory* opens fine). Diagnosis trap: the discriminators are a flags A/B on one mount (NODEV on/off) and the absence of any `avc`. Fix: devpts mounts `MS_NOSUID` only (`src/sandbox/mounts.rs`); the fresh `/proc` keeps NOSUID/NODEV/NOEXEC (no device files under proc). |
| 40 | The `run` teardown must not destroy a sidecar socket sharing the instance dir | The per-instance runtime dir (decision #28) is **shared**: the `--proxy` relay, the `dbus-proxy` sidecar, and the `xwayland` satellite all bind their public socket there, and a sidecar's listener outlives every `run` that shares the instance. The historical teardown was a blind `remove_dir_all` on every exit: the sidecar's listener fd survives the unlink, but its path is gone — the next `run`'s carry hands the sandbox an *empty* dir and the app finds no compositor. The fix is both halves of the lifecycle. (a) **Teardown** (`remove_runtime_dir`/`sweep_runtime_dir`): the dir is swept level by level; each **socket** is liveness-probed with `connect(2)` (the same test `bind_socket` uses when refusing to steal a live socket) and kept while served (the probe connection is dropped immediately), stale ones are removed, **its own** tagged socket is unlinked by path without probing, and the dir is `rmdir`'d only when nothing live is left — the cleanup is **lazy**, so the sidecar never has to clean up after itself. (b) **Sidecar (re)start** (`bind_socket`): `bind(2)` needs the parent dir, which the last teardown may have removed, so the bind recreates it first (owner-only 0700, tightened only when *we* just created it — a pre-existing dir keeps its mode, so an ad-hoc `--listen /tmp/x` must not re-mode `/tmp`); this also fixes the SIGHUP in-place re-exec. All teardown steps are best-effort: a failure loses only hygiene, never the run's result. Verified e2e (v2.14): a relay bound before a `run` survives the teardown, and the next `run` reaches the compositor through it. |
| 41 | A run must not orphan the app's namespace when the pipeline dies mid-run | **Run #1**: S died silently mid-run (the cause was never identified — no core, no journal event, no error line), A died shortly after, and the app's pidns (B is its PID 1 — #13: immune to default-action signals from outside) ran on forever; the only trace was the sub-cgroup `rmdir` failing `ENOTEMPTY`. Two holes can produce that cascade; both are closed (v2.15, LESSONS #37). (a) **`EINTR` was fatal in both reapers' blocking `waitpid`s** (S's through `?`, A's through a 126 exit): both block *exactly* the three signals they forward (the signalfd is their sole consumer), so every other signal is at default disposition and *delivered* — and a delivered signal interrupts `wait4`; `waitpid_retry` loops on `EINTR` in both (a dead A reaps nothing; a dead S takes the 2 s KILL escalation — the only thing keeping B finite). (b) **No backstop for any other S exit with the app alive** (an error `?`, a panic, a dead A reaped by S): the `AppKillGuard` is armed when the handoff completes and dropped at run's end; its `Drop` reads the instance sub-cgroup's `cgroup.procs` (recursive on cgroup2 — A + B + every descendant) and SIGKILLs whatever is alive. It does *not* rely on the kernel's zap of a dying pidns init (#14: on 7.2.11 strays reparent and survive); on the normal path the sweep is an empty no-op, and it fires — loudly — only when a live process is found, i.e. exactly the incident. **Field-verified** by SIGKILL-ing A (old code: B+child immortal, `rmdir` `ENOTEMPTY`; new code: no process left). **Remaining boundary:** a *default-terminate* signal **to S itself** kills the guard with it (`Drop` runs only on unwinding exits, not on a fatal-signal death) — the actual run-#1 shape; closed by the `PR_SET_PDEATHSIG` cascade (#42). |
| 42 | A S-death the `AppKillGuard` cannot intercept (a default-terminate signal to S itself) must still end the app (the run-#1 boundary left by #41) | The guard dies with S, so this needs a kernel-level `PR_SET_PDEATHSIG` cascade where each process's death propagates to the process it supervises (`src/pdeathsig.rs`; v2.16). **A←S:** A sets `pdeathsig = SIGUSR1` right after its first fork (before the unshare; A never execs, so it survives). Deliberately USR1, not TERM: A keeps the pre-fork TERM/INT/HUP block (it must survive a group-wide Ctrl-C until it reaps B), a pdeathsig that lands in a block stays *pending* forever, and nothing else in the pipeline sends USR1 — so the signal means exactly "S is gone". The handler is installed *after* the second fork (B does not inherit it — B's USR1 stays at its default-kill disposition, the pre-exec answer to "A is gone") and only stores a flag; the delivery `EINTR`s A's blocking `waitpid`, `waitpid_retry` reports it *unwrapped*, and A kills B and exits 137. **B←A:** 7.2 `fork` *resets* `pdeath_signal` to 0 (not inherited), so B re-arms USR1 itself right before its exec; a confined exec changes the process's SID, and `selinux_bprm_committing_creds` **unconditionally** zeros pdeathsig on *any* SID change (`security/selinux/hooks.c:2545`, `4ac212ad4e8f`) — so an `LD_PRELOAD` shim re-arms it after the exec. Of the 7.2.11 clearing paths (a *denied* `noatsecure` — granted on `apse_t → apse_app_t` but not on the `xserver_t` transition; an actual credential change — does not fire, same uid; the unconditional SID-change clear) none fire on a *same-domain* exec, so the belt survives: the shim is built only in confined mode (field-verified necessary, LESSONS #19-#20), where `ensure_shim` also relabels the `.so` to `apse_shim_t` and compiles it under a *pinned* exec context (LESSONS #41-#42). The same module serves the `xwayland` satellite (`SIGTERM`); the shim file is signal-suffixed. **Field-verified on both legs (2026-11-03, v2.17, LESSONS #44):** SIGKILL S → the belt's USR1, A's handler tears B down; SIGKILL A → the belt's USR1 observed in B (strace `si_code=SI_USER`, `si_pid=0` — the cross-pidns pdeathsig marker, a kernel-internal delivery invisible to the audit exit filter), and the `AppKillGuard` sweep ends the run, no orphans. The one piece not cleanly isolated (not load-bearing while the guard exists): B's own USR1-terminate disposition (B resumed via `restart_syscall` — an `SA_RESTART` action is suspected — and died on the guard's KILL, not the belt's). |
| 43 | The app's `$HOME` and XDG dirs: the real home, or a private per-app state? | **Default: a private per-app state tree** (2026-11-11; the container-era per-app home volume, re-implemented as binds). The profile's `home` mode defaults to `"private"` (ad-hoc and built-in): S creates, before the first fork, a **per-app (not per-instance)** tree at `$XDG_STATE_HOME/apse/<app-id>/` (home/config/cache/data/state subdirs, all 0700 — with the default state dir, `$HOME/.local/state/apse/<app-id>/`) and never removes it — it *is* the app's persistent state; the rootfs build (step 7) binds its subdirs over `$HOME` and the XDG locations. Order and traps: the tree is carried into the step-1 scratch *before* the real home is replaced (a source resolved after that bind would hit the private copy — #28's trap); the binds go home → config → cache → data → **state last** (a state dir may nest under the data dir, and each target must resolve after the binds beneath it); targets under the home are pre-created by S, a custom XDG outside the home only when it exists. The app's environment keeps its historical XDG strings — the redirect is invisible. **CWD:** in private mode B `chdir`s to the app's home before the exec — the inherited CWD is the host's launch dir, which disappears when the real home is replaced, and an app that forks and `chdir(cwd)`s before its exec (foot's `slave_spawn`) dies on the bad chdir; host mode keeps the inherited CWD. `home = "host"` keeps the pre-8.3 behaviour (real dirs rw self-bound); the profile's `rw_binds` layer on top in both modes. Landlock: one ReadWrite grant per existing target (the same strings in S and B resolve through the binds to the state-tree inodes); the mode is validated before the fork. **Confined mode** (refined v2.21): the tree is the module's dedicated `apse_state_t` — the `apse` root that `apse_t` creates under `~/.local/state` (`gconf_home_t`) is *born* `apse_state_t` via a named filetrans (the five-field `typetransition` in this module store's CIL dialect — no `filetrans` keyword; on this kernel `filecon` does not label created inodes), and the no-rule default makes the whole subtree inherit it; S's setxattr walk does the one-time migration of a pre-module (gconf-labelled) tree and self-heals stragglers. S gains the dir create/setattr/`mounton`/relabel grants; the app gains the full file lifecycle on the tree (incl. fish's `lock`/`watch`) plus `entrypoint`/`execute`/`execute_no_trans` on `apse_state_t` files (B's exec-context exec, and its own children) and the `apse_t → apse_app_t` fallback transition; `unconfined_t` gains the user's inspection lifecycle (full grant list: `selinux/README.md`). Field-verified (2026-11-12): `ps ax` directly through a confined `apse run`, zero denials. **Tests:** the rootfs reference test asserts a `$HOME` write lands in the per-app state tree, never the real home; the integration suite adds a hermeticity marker and a private-home write to the Landlock probe. |
| 44 | The `home = "host"` profile mode (the legacy half of #43) | **Dropped** (2026-11-13, task 8.9): since v2.20 the private home has been the default and the only mode in use; `"host"` was pre-8.3 compatibility. Its costs — 14 module rules (the app-side `*_home_t` dir/file grants, the `apse_t → {user_home_t, gconf_home_t}` app transitions and their `process` mirrors, none of which a private-home sandbox can reach), mode branching in `policy.rs` / `mounts.rs` / `mod.rs`, and doc spread over four files — outweigh a convenience mode the threat model describes as "the isolation is from *other* users and the *system*, not from you". The profile's `home` field is removed entirely: `deny_unknown_fields` makes a `home = "…"` line a hard parse error, which is the migration signal (no built-in profile sets the field). The private home becomes unconditional: `prepare_app_state` always runs, the step-1 carry and the step-7 binds have no branch, and B's pre-exec `chdir` is unconditional. **Kept, because mode-independent:** the supervisor-side home rules (profile lookup and traversal, the state-tree creation, the one-time relabel migration walk) and the app-side *path-traversal* grants (`home_root_t` / `user_home_dir_t` — the bind target still sits at the real `/home/<user>` path). An app wanting specific *non-home* host paths still has `rw_binds`; home-subtree paths stay unreachable by design (that is the isolation). |

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
  target (decision #43: the private per-app tree — the only mode
  since #44);
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
- [x] 8.2 New SELinux policy: the local module confining the
      supervisor and app domains; the bind-mounted `/dev` nodes keep
      canonical labels, which makes this tractable — see §3.3.
      **Done 2026-10-28 → 11-04** (`selinux/apse.cil`; decision #38 —
      design and current state: `selinux/README.md`). Built from the
      permissive **container-selinux probe** of 2026-10-28: apse run
      under podman's own two domains — the S/A runtime side as
      `container_runtime_t` with **zero genuine denials** (crun does
      exactly this work, so the shipped rules cover it; the full chain
      incl. the `--proxy` relay into live sway ran clean) and the app as
      `container_t` (the rebuilt rootfs' fresh `seclabel` tmpfs
      `/tmp`/`/dev`/`/run` inherit the creator's exec label for free;
      `/proc` reads, loopback, `/dev/urandom` covered; `/dev/dri` via
      the tunable). The probe's deduped AVC inventory is the module's
      template, and the zero-new-policy option it exposed (label the
      binary `container_runtime_exec_t`) is #38's rejected alternative.
      Installed as pure CIL (`sudo semodule -i` — one command for rules
      *and* file contexts; LESSONS #24-28). The enforcing-mode tuning
      loop (2026-10-29) iterated audit2allow against a confined run
      until **zero denials across nine consecutive runs** — closing two
      code bugs the loop forced (LESSONS #30-#31), an intra-app *pipe*
      self-`fifo_file` gap the test never exercised (LESSONS #32), and
      the supervisor's `/proc/<pid>/cwd` `lnk_file read`. The
      **default_range** investigation corrected the early MCS
      assumption: the per-instance MCS isolates the instance's
      **processes**, not its **objects** (created objects are `s0` —
      file separation is the namespaces + landlock rootfs; LESSONS
      #29), and this kernel's `signull` (kill -0) is outside the base
      mlsconstrain, so the `terminate_app` kill -0 probe is not
      category-scoped (LESSONS #33). The 8.5 threat-model review was
      re-checked against the findings (2026-10-29). The last item —
      confined-mode field verification of the `dbus-proxy`/`xwayland`
      satellites and the broker — completed 2026-11-04, kernel 7.2.15
      (v2.18; zero denials; LESSONS #45-#46).
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
- [ ] 8.6 *(future)* Per-invocation `--no-selinux` flag (env
      `APSE_NO_SELINUX`): run one invocation unconfined while the
      binary stays confined by default. The current escape is the
      binary's *file label* (`semodule -r` / `chcon` back to stock,
      `selinux/README.md`) — root-only and persistent; this is the
      unprivileged per-invocation form. Scope: the `run` pipeline
      first; the satellites are separate processes the user starts
      anyway and can take the flag later.
      **Mechanism — a one-time self re-exec, not flag checks.**
      `apse_t` is a property of the *file*: the S/A/B forks inherit
      it regardless of any in-process flag, and B's exec of the app
      still fires the module's `apse_t → apse_app_t` typetransition —
      so merely skipping the MCS/shim checks does not un-confine the
      *app*. With the flag set and `is_confined()`, `main` writes the
      pre-module exec context (the binary's stock label —
      `unconfined_t` per the module README; pin the exact context in
      verify) to `/proc/self/attr/exec` and re-execs
      `/proc/self/exe` with the original argv (flag included) —
      reusing the MCS self-narrowing re-exec's one-time shape and
      loop guard (the second entry sees `is_confined() == false` and
      proceeds; the LESSONS #30/#31 NUL / no-`O_CREAT` traps apply to
      that write too). From there the whole pipeline *is* unconfined
      mode: no MCS, no shim, no exec-context writes, the app keeps
      its own file label — exactly as if the binary had never been
      relabeled.
      **Module side:** the `apse_t` self-exec to the stock type
      needs an explicit `type_transition apse_t apse_exec_t
      process <stock-type>` plus the `process:transition` allow —
      the MCS narrowing proves the exec-context write path; the new
      part is a *type* change. Add the rule and confirm with the
      tuning loop (zero new denials).
      **Verify** (target machine, confined binary, enforcing):
      (a) `run --no-selinux <probe>` — an in-sandbox
      `/proc/self/attr/current` probe shows the stock context, the
      app runs in its own type (not `apse_app_t`), zero denials;
      (b) the same invocation without the flag stays confined
      (regression guard); (c) the re-exec fires exactly once.
      CI is unaffected — the test-suite binary is unrelabeled, so
      the flag is a no-op there.
- [ ] 8.7 *(future)* In-sandbox debugging: a boolean-gated `ptrace`
      grant (`apse_app_ptrace`, off by default) + a `debug`
      profile/flag that validates it: run gdb/strace *inside* a
      confined run, debugging processes within the same instance.
      **The denial (audit-verified, v2.25 enforcing):** a debugger
      running as the app is refused `ptrace` on the process it
      wants to debug — five denials from strace and gdb, all
      `scontext = tcontext = apse_app_t:s0:c1007`, `tclass=process`,
      `permissive=0` — i.e. a missing **self**-grant: the v2.25
      mirror of `domain`'s self-grants omits `process:ptrace`
      because the base `domain` does not ptrace itself. **The split
      that matters:** *host-side* debugging already works —
      `unconfined_t → apse_app_t` carries `ptrace` (the "user can
      trace" line) and `strace -p` / `gdb -p` from an unconfined
      shell attach cleanly (verified live, 2026-11-13) — so 8.7
      only concerns the *in-sandbox* debugger.
      **Mechanism — a boolean, because SELinux has no per-
      invocation policy.** Policy is global kernel state; a per-
      invocation *grant* is impossible (as with 8.6, `apse_t` is a
      property of the file, not of a run). So: `gen_bool
      apse_app_ptrace false` plus the self-grant `(allow
      apse_app_t apse_app_t (process (ptrace)))` inside `(if
      (boolean apse_app_ptrace) …)`. **The toggle is root-only:**
      `setsebool` as a regular user fails EACCES (verified
      2026-11-13 — `unconfined_t` has no `boolean:write`), so the
      toggle is `setsebool -P apse_app_ptrace on` by root — the
      "setsebool option" from the bug report, but persistent and
      system-wide. An unconditional (un-gated) grant is
      defensible — the self-grant is MCS-bounded in effect (module
      note near the self-grant block): the only processes sharing
      the app's `cN` are its own tree in the *same* instance, so it
      cannot reach other instances, the supervisor (`apse_t`), or
      the host — but default-off + boolean keeps "least by
      default" and gives an off switch.
      **Per-invocation UX (flag/profile, grants nothing):** a
      `debug = true` profile key or `--debug` flag that (a) reads
      the boolean (unprivileged — it is a file read) and fails
      fast with a clear message if it is off, and (b) records in
      the profile that the entry command is a debugger.
      **Usage is same-instance by construction:** the debugger is
      the app (`apse run -- gdb ./target` — it forks+execs and
      ptraces its own child) or attaches within one instance
      (`apse run -- sh -c 'app & strace -p $!'`); a *separate*
      instance cannot debug another (different `cN`, MCS blocks —
      by design; use the host-side path).
      **Expected scope of the grant:** `process:ptrace` alone may
      close it — the `/proc/<pid>` tree carries the *target's* own
      context on this kernel (LESSONS #45, module note), so a
      debugger's reads of the target's `mem` / `maps` / `cmdline`
      are checks against `apse_app_t` self, which the existing file
      self-grants cover (`open` / `read` / `map`). The tuning loop
      (zero-denial goal) decides anything more. The same audit run
      also showed one `netlink_audit_socket: create` denial from a
      shell — do **not** grant by default (an app reading the
      audit log can observe other processes' denials); revisit only
      if a legitimate app needs it.
      **Verify** (target machine, confined binary, enforcing):
      (a) boolean off: in-sandbox strace/gdb denied as today
      (baseline unchanged); (b) boolean on: `gdb` on a small C
      target and `strace` on an in-instance child attach/detach
      cleanly — zero denials across the whole debug session;
      (c) cross-instance: a debugger in instance A against a
      process in instance B — still denied (MCS intact);
      (d) host-side `strace -p` unaffected; (e) a normal run
      (boolean off, no debugger) — zero denials, no behavior
      change. Document in `selinux/README.md` (Operating modes →
      debugging) and in AGENTS.md.
- [x] 8.8 Dedicated-type exec grant — the `hostname` / `ip`
      denial class (2026-11-13, v2.32): stop chasing the
      distribution's per-binary exec labels. **As implemented
      (refined from the original `exec_type` plan):** the grant
      targets the base **`application_exec_type`** attribute
      instead — checked with `seinfo -a <attr> -x` (the
      compiled membership oracle: this `sesearch` does not
      resolve attribute membership in rule queries), that is
      311 members, a strict subset of `exec_type`'s 1048. The
      exclusion is exactly the intended boundary: init scripts,
      server daemons, inetd services — plus the generic
      catch-alls `bin_t`/`shell_exec_t`/`usr_t`, which are
      `exec_type` members but *not* `application_exec_type`
      members (on this box the attribute is the *dedicated* set,
      not "most normal binaries" — LESSONS #76). Those three
      keep their enumerated rules, so the union (attribute +
      catch-alls) is everything but the daemon/init dedicated
      types, and nothing about the generic tools changes.
      *Both levels* got the full exec union (`entrypoint
      execute execute_no_trans getattr map open read` — plus
      `ioctl` at the child level): `apse_t` (absorbing the
      former `xserver_exec_t`/`apse_exec_t` file rules — both
      members) and `apse_app_t`. No `noatsecure` at either
      level: a setuid exec runs setuid-stripped (secure-exec —
      the kernel leaves the euid at the caller's), so
      `su`/`pkexec`-class tools gain nothing; verified: `su`
      execs but cannot authenticate (its setuid-root helper
      `unix_chkpwd` is equally stripped — no escalation),
      `pkexec` (not a member) stays denied, and DAC remains the
      backstop. **The generic (attribute-object)
      `typetransition` did not happen** — infeasible, not just
      unverified (LESSONS #77): the transition table is
      single-valued on (subject, objtype, class), and
      `xserver_exec_t` is an `application_exec_type` member
      that must keep its own `xserver_t` target (the Xwayland
      satellite), so a 311-member expansion collides at
      install. The app transition set therefore stays
      enumerated (one line per dedicated-type app actually
      run): `mozilla_exec_t` (Firefox) and `hostname_exec_t`
      (the standing dedicated-type-app probe) were added.
      **Follow-on (the functional half, done):** `ip` needed
      two grants — `process:setcap` (iproute2's startup
      `capset(2)`; always self-targeted, privilege-neutral
      here) and the `netlink_route_socket` self-grant (this
      7.2 kernel's netlink classes carry separate
      `nlmsg_read`/`nlmsg_write` permissions; `getsockname` is
      the distinct `getattr`; the socket is born in the
      creator's context — no `sockcreate` filetrans — so the
      grant is self-targeted and MCS-bounded). `hostname` get
      mode needed nothing more; **set** mode is intentionally
      *not* granted (the UTS hostname is the instance's private
      identity, set by apse at sandbox init). Deliberately
      *not* granted (accepted, the "Deferred denial classes"
      list): `ping`/`traceroute` raw and ICMP sockets (a
      packet-sniffing capability in a shared netns — a separate
      policy decision, not a tooling convenience),
      `netlink_audit_socket` (8.7), and `journalctl`'s journal
      reads (the fresh `/run` carries no runtime journal; the
      persistent one is host data). The narrow
      `exec_type:file:getattr` rule stays — it is now precisely
      the stat() path for the `exec_type` remainder outside
      `application_exec_type` (the daemon/init trees, e.g.
      `ls -l /usr/sbin`). The `exec_type`-wide variant would
      only have bought a slimmer rule list (net −6 vs the
      actual +4) at the cost of exec surface over 737 extra
      types that are DAC root-only for a real-uid app anyway;
      the structural gain (no more rule+rebuild+retest per
      dedicated type; immune to distro filecon relabels) is the
      same either way. **Verified** (enforcing; the battery in
      the v2.32 change-log entry): baseline reproduced
      pre-change (`route` OK; `ip`/`hostname` `file:execute`
      denied at both levels); after — child level: `ip link`/`ip
      addr` with a full RTNL round trip, `hostname` (prints
      `apse-<app>-<inst>`), `gpg --version`, `journalctl`
      (executes), `su` (execs, stripped, no escalation) — zero
      `file:execute` denials; app level: `apse run --
      /usr/bin/hostname` starts and the in-sandbox
      `/proc/self/attr/current` shows `apse_app_t:s0:cN` —
      zero denials; the full suite (231 tests, single-threaded)
      passes. Documented in `selinux/README.md` (The
      dedicated-type exec world).
- [x] 8.9 Drop the `home = "host"` profile mode (2026-11-13,
      v2.31) — per decision #44 the private home is the only mode.
      **What
      goes** (everything host-mode only; the private home is
      untouched): (1) *Code:* `src/profile/mod.rs` — the `home`
      field, its `"private"` default, and `private_home()`; with
      `deny_unknown_fields`, a `home = "…"` line in a user TOML
      is now a hard parse error — the migration signal (no
      built-in profile sets the field). `src/sandbox/policy.rs` —
      the `home.as_str()` validation match and its host-mode
      comment; the home/XDG landlock loop stays (the same strings
      resolve to the state-tree inodes in B's namespace either
      way). `src/sandbox/mounts.rs` — three branches become
      unconditional: `prepare_app_state`'s early return, the
      step-1 state-tree carry, and step 7's else half (the legacy
      rw self-binds of home/config/cache/state/data); rewrite the
      step-7 comment and the module doc to the single mode.
      `src/sandbox/mod.rs` — B's pre-exec `chdir` (the
      private-home branch) becomes unconditional (the warn
      fallback stays). (2) *Module — 14 rules* (the app-side
      home family; every supervisor-side home rule stays): the
      `apse_app_t` dir+file grants on `user_home_t` /
      `cache_home_t` / `config_home_t` / `data_home_t` /
      `gconf_home_t` (~858-880), the two `apse_t →
      {user_home_t, gconf_home_t}` `apse_app_t` typetransitions
      (~271/276 — the app-binary-in-the-real-home case) and
      their paired `process (noatsecure rlimitinh siginh)`
      mirrors (~297/298; no process of those types can exist in a
      private-home sandbox). Stays: the supervisor-side profile
      lookup and traversal (~437-450), the state-tree creation
      (the named filetrans ~294 + its parent-dir grant ~460), the
      one-time relabel migration walk (~501-510), and the
      app-side *path-traversal* grants (`home_root_t` /
      `user_home_dir_t` ~856/857 — the bind target still sits at
      the real `/home/<user>` path). The home-family
      `cil_gen_require` lines stay (still referenced). (3)
      *Docs:* README (the rootfs-build step-7 description, the
      profile example, and the threat-model home paragraph — the
      `home = "host"` opt-in sentence goes), `selinux/README.md`
      (the confined-mode summary line), and this file's
      architecture-table row. **Breaking change (accepted,
      personal repo):** a profile TOML with `home = "host"` stops
      parsing (unknown field) — delete the line; an app wanting
      specific *non-home* host paths still has `rw_binds`, while
      home-subtree paths are unreachable by design (that is the
      isolation). **Verify:** (a) `cargo test --locked --
      --test-threads=1` green with the rewritten profile test
      (asserts `home = …` is rejected); (b) enforcing confined
      live run — reinstall the module per `selinux/README.md`
      (Operating modes) and run a GUI app (foot) plus a shell
      app under the default profile: zero new denials, audit
      baseline flat — this exercises every kept supervisor rule
      (profile read, state-tree creation, the migration walk,
      both traversal families); (c) an unconfined run unchanged;
      (d) a `home = "host"` profile fails at parse with the
      unknown-field error.
- [x] 8.10 Per-instance `/etc` files (2026-11-13, v2.30): the UTS
      name `apse-<app>-<inst>` resolves on loopback with no DNS
      fallback. A generates `hosts` (the localhost lines, then
      `127.0.0.1 <name> <name>.localhost` (the loopback users have
      learnt to expect, and what systemd's nss-myhostname answers —
      the user's call over the stock file's `127.0.1.1` alias) —
      **constant content, not a verbatim copy of the host's file**:
      static for the instance's lifetime, stable label, never
      mutated by host drift) and `hostname` (= the UTS name) into
      the **per-instance runtime dir**
      (`$XDG_RUNTIME_DIR/apse/<inst>/etc/` — under the /run tmpfs,
      not the scratch: the user's call, 2026-11-13), and the new
      **step 7.5** (between the home binds and the `/var` mask)
      binds both over the self-bind-layer `/etc` as single files
      (the targets must exist on the host — a user-owned build
      cannot create files in the root-owned `/etc`; the sources
      ride the step-1 runtime carry and are removed with the
      runtime dir at teardown). Static for the instance's lifetime
      (a known limitation): an in-sandbox `hostname <new>` changes
      the UTS name without touching the files — the *instance*
      name still resolves. Access is **read-only**: the single-file
      binds leave the inodes out of the `/etc` dentry tree, so the
      dir grants do not reach them — Landlock gets file-level
      `Read` grants (`allow_file` on the `/etc/…` paths; the
      kernel accepts a file fd as a `PATH_BENEATH` parent for a
      file-access subset) in unconfined mode, and `apse_etc_t` in
      confined: born by named filetrans under the runtime dir's
      `user_tmp_t` parent (the `tmp_t` parent was right for the
      scratch era; `filesystem:associate` against `tmpfs_t` —
      `/run` — and `fs_t` for an off-default XDG, because
      `may_create` checks the *new label's* SID), read-only for
      `apse_app_t`, plus `getattr`+`mounton` on the bind targets'
      `net_conf_t`/`hostname_etc_t` (the build's exists-check
      stats them). **Verified:** unconfined and `--network=none`
      (in-sandbox `/etc/hostname` == UTS, the name resolves to
      loopback in both modes, the host's `/etc/hosts`
      byte-identical, a write attempt `EACCES` in *both* modes —
      in confined the Landlock floor answers before SELinux, so
      the audit baseline stays flat); confined enforcing probe
      (python3, shared netns) with **zero denials** after the
      filetrans parent change; the integration case
      `etc_files_are_per_instance_and_readonly`
      (`tests/sandbox_integration.rs`, both network modes). S
      startup cost unchanged (two small file writes). **Deferred**
      (spec sub-part, revisit if an app needs it): the
      `--network=none` `resolv.conf` extension (host's file with
      the `nameserver` lines stripped) — none mode's bare
      loopback netns already fails every lookup immediately (no
      route, no timeout), and shared mode keeps the host's file.
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