# apse on AppArmor (no SELinux) — design sketch

Status: **parked future item** (written 2026-11-11). No code or
profiles exist for this yet; this is the working sketch to return
to. The one open kernel question that decides the shape of the
work is in §2.2.

The question this documents: what would it take to run apse with
**AppArmor as the confinement layer instead of SELinux** — i.e. on
distributions whose default LSM is AppArmor (Ubuntu, Debian) rather
than SELinux (Fedora).

## 1. The baseline needs no changes

apse with SELinux off and AppArmor on is exactly the **unconfined
mode** this project already runs in, and it already works on
AppArmor machines. Evidence: CI runs the full suite on
`ubuntu-latest` (Ubuntu 26.04), where AppArmor is enforcing — the
`kernel.apparmor_restrict_unprivileged_userns=0` step in
`.github/workflows/ci.yml` exists because AA is active there and
restricts unprivileged `CLONE_NEWUSER` (the AGENTS.md "CI runner"
Facts bullet documents the mechanism). In that mode:

- every `src/mcs.rs` function is a no-op (`is_confined()` is
  false — the current SELinux label's type is not `apse_t`),
- the run pipeline does not build the pdeathsig shim
  (`sandbox/mod.rs` gates `ensure_shim` on `is_confined()`),
- the `xwayland` satellite builds its shim unconditionally, but
  the re-arm is an idempotent no-op without a SELinux SID change.

The core isolation — namespaces + the rebuilt rootfs + landlock/
seccomp via nono (decision #27) — is LSM-agnostic, as is the whole
tagged-socket / proxy / broker stack (the `wp_security_context_v1`
path is compositor-side, not LSM-side). **Nothing blocks running
apse on an AppArmor distro today.**

So the real question is the same one phase 8.2 answered for
SELinux: what does the **second layer** — domain confinement of
the apse stack as defense in depth against a sandbox failure —
look like in AppArmor? The SELinux module (`selinux/apse.cil`)
provides three distinct things; each maps differently.

## 2. What SELinux provides, and the AppArmor equivalents

### 2.1 The three domains become three profiles

| SELinux | AppArmor | Consequence |
|---|---|---|
| file type `apse_exec_t` + `restorecon` to arm the transition | **executable-path** matching (`profile apse /usr/local/bin/apse`) | No relabel step — loading the profile *is* the install (`apparmor-parser -W …` + service restart, verify with `aa-status`). Simpler than the SELinux path: no CIL/`.te` format pitfalls, no `restorecon` |
| `typetransition apse_t bin_t process apse_app_t` | child (nested) profile + `change_profile` at exec | see §2.2 |
| `apse_shim_t` relabel so a confined consumer may `PROT_EXEC`-map the shim `.so` | AppArmor has **no file-type execute permission** — a `PROT_EXEC` mmap only needs *read* on the file | the `apse_shim_t` relabel and the pinned-`cc` exec-context logic in `pdeathsig.rs` both drop out for the AA path |
| MCS categories `cN` (per-instance) | **no equivalent** — profile names are static | see §3 |

The domains map one-to-one:

- `apse` (≈ `apse_t`) — the supervisor domain: S→A→B pipeline,
  rootfs mounts, the per-instance runtime dir and its sockets,
  the session bus, spawning the satellites, and the `userns`
  work. This is where `capability sys_admin, sys_chroot,
  sys_ptrace, net_admin, dac_override,` (the CIL's `cap_userns`
  set), the `mount`/`umount` lines and the cgroupfs `rw` grants
  go. Note: B does `unshare(CLONE_NEWUSER)` **before** its exec
  into the app, so at that moment it still wears the `apse`
  profile — any AppArmor `userns` permission item (see §5) goes
  here, not in the app profile.
- `apse_app` (≈ `apse_app_t`) — the sandboxed app: home/cache/
  config, font trees, `/dev` nodes, `/proc`/`/sys`, `/dev/shm`,
  session-bus connect, loopback-capable sockets. **No
  capabilities, no mount.**
- `apse_xserver` (≈ the module's `xserver_t` grants) — the
  Xwayland satellite: the X socket, the MIT auth file, dri.

The CIL grants translate mechanically into AppArmor rule lines
(the same audit-driven loop as the SELinux tuning would apply):
`bin_t`/`lib_t`/`ld_so_t` file reads map to `/usr/bin/** r,
/usr/lib/** r, …`; the `unix_stream_socket connectto` grants map
to path rules on the socket endpoints (AppArmor has no D-Bus
class — bus mediation is just file access on
`/run/user/<uid>/system_bus`); the `node tcp/udp` grants map to
`network inet stream, network inet6 stream` (the *loopback-only*
restriction was never SELinux's — it's landlock's, and stays
landlock's); the `fd:use` grants (the keymap shm fd received via
`SCM_RIGHTS`, the satellite's inherited socketpair) map to
`/dev/shm/** r` and the runtime-dir socket rules, with the same
`MSG_CTRUNC` failure mode if a grant is missing.

Illustrative shape (not final):

```
# /etc/apparmor.d/apse
#include <tunables/global>
profile apse /usr/local/bin/apse flags=(attach_disconnected) {
  #include <abstractions/base>
  capability sys_admin, sys_chroot, sys_ptrace, net_admin, dac_override,
  mount, umount,
  /usr/local/bin/apse r,
  /usr/bin/** r, /usr/lib/** r,
  @XDGRUN/apse/** rwk,                     # per-instance runtime dir
  /sys/fs/cgroup/user.slice/** rw,         # (Ubuntu path; differs on Fedora)
  /dev/null rw, /dev/urandom r, /dev/dri/renderD* rw, /dev/pts/** rw,
  /proc/** r, /sys/** r,
  network inet stream, network inet6 stream,

  # nested child profiles: the transition targets are *defined in*
  # the parent, which avoids any separately-loaded-profile
  # (child-profile) version question
  profile apse_app { … no caps; home/cache/fonts/dev/shm/proc/sys/bus … }
  profile apse_xserver { … X socket, auth file, dri … }
}
```

### 2.2 The exec transition, and the one open question

`mcs::set_exec_context` writes `/proc/self/attr/exec` — that file
carries the `security.selinux` exec context and is
SELinux-specific. The AppArmor equivalent of "transition on the
next exec" is the classic `change_profile` mechanism, which
libapparmor's `aa_change_profile()` implements as:

1. write the target profile name to `/proc/self/attr/apparmor/current`
2. `prctl(PR_SET_SECURECOMPUTING, 1)`

That is two calls on `libc::prctl` — no new crate. The call sites
stay where they are (B pre-exec, `xwayland.rs`, `dbus_proxy.rs`);
only the backend of `set_exec_context` changes.

**Open question that decides the shim:** AppArmor's exec hook
(`apparmor_bprm_creds_for_exec`) can also set `bprm->secureexec`
on profile transitions — historically that is what it does for
transitions to a *non-child* profile, which would clear
`PR_SET_PDEATHSIG` exactly like the SELinux SID-change clear
(`selinux_bprm_committing_creds`, `security/selinux/hooks.c:2545`,
the mechanism the pdeathsig shim exists for, decision #42/#37,
LESSONS #19-20). A transition into a *nested child* profile is
intended to be the "secure" (non-clearing) case, but that is the
kind of claim this project probes, not assumes. **Probe:** after
a `change_profile` + exec in a throwaway test binary, read
`prctl(PR_GET_PDEATHSIG)` (or use the shim's own delivery
signature — `si_code=SI_USER`, `si_pid=0` under strace). If the
belt survives → the run-pipeline shim gate stays off (no change
from today). If it's cleared → keep building the shim for the AA
path too, minus the two SELinux-only steps (the `apse_shim_t`
relabel and the pinned `cc` exec context, both of which drop out
in §2.1). The shim's C source itself doesn't change either way —
the mechanism is already LSM-generic.

### 2.3 Detection and the mode plumbing

`is_confined()` currently reads `/proc/self/attr/current` and
tests the type for `apse_t`. The natural generalization is a small
backend enum detected once at startup: `None | Selinux |
Apparmor`, where AppArmor = `/proc/self/attr/apparmor/current`
names our profile (it reports `unconfined` as a bare string, or
the profile name with a mode suffix under the newer profile
format). Under AppArmor, `instance_category`,
`self_reexec_with_category` and the broker's
`self_reexec_to_s0` are no-ops (the one-time self-reexec slot
stays in the code as the future home of per-instance profile
loading, §3).

## 3. MCS has no AppArmor equivalent — and most of its value was redundant

AppArmor labels are static profile names; there is no per-instance
dimension, so the `cN` category (and its teeth — a single
category is incomparable with any other, so a `cN` subject may
only signal/ptrace/transition a same-`cN` process, LESSONS #29)
has no direct translation.

What that actually loses:

- **App vs. other instances' apps: nothing.** The app is in its
  own pid namespace and cannot even *see* the other instance's
  pids; the MCS teeth there were belt-and-suspenders.
- **Host-side members (two instances' S/A supervisors,
  satellites):** same uid and (without generated per-instance
  profiles) the same profile, so a `signal` rule cannot
  distinguish them. AppArmor's default signal policy (no `signal`
  rule in the profile) falls back to the usual uid checks — which
  is **exactly today's unconfined-mode behavior**: no regression,
  just no bonus.

If per-instance process isolation is ever wanted on AppArmor, the
mechanism would be *generated per-instance profiles* (same FNV
hash as `instance_category`, profile name `apse-app-<cN>`, loaded
at the one-time self-reexec slot) — but loading profiles needs
the `apparmor` service or write access to
`/sys/kernel/security/apparmor/profiles` (i.e. root or the
apparmor socket), so it would be its own work package, not part
of the base design.

An honest `apparmor/README.md` (when the profiles land) would say
plainly what the layer is and isn't: a second layer of
path/capability confinement of the whole stack; not
cross-instance process isolation, and not the loopback
restriction — those are the pidns's and landlock's jobs.

## 4. The code diff surface

| File | Change |
|---|---|
| `src/mcs.rs` (perhaps renamed `src/confinement.rs`) | detect the backend once (`None`/`Selinux`/`Apparmor`); `set_exec_context` gains an AA arm (write `/proc/self/attr/apparmor/current` + `prctl(PR_SET_SECURECOMPUTING, 1)`); the category/reexec functions no-op under AA |
| `src/pdeathsig.rs` | drop the two confined-mode-only steps (shim relabel, pinned `cc` exec context) when the backend is AA; shim source unchanged; whether the run-pipeline shim builds at all depends on the §2.2 probe |
| `src/sandbox/mod.rs`, `src/xwayland.rs`, `src/dbus_proxy.rs` | unchanged — they call `mcs::set_exec_context`, which just picks the backend |
| everything else (proxy, broker, tagged socket, profiles, units) | **untouched** — already LSM-agnostic |
| `apparmor/` (new, mirrors `selinux/`) | the profile file(s) + README, when the work lands |

## 5. Environment prerequisites on the test VM

- **First step on any Ubuntu VM is the same as CI's:**
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
  (Ubuntu enables the restriction by default; it denies the
  unprivileged `CLONE_NEWUSER` *sequence* — the unshare succeeds,
  the `setgroups` write is refused — for *all* unprivileged
  processes, so it applies to apse in unconfined mode too).
  Alternative on new enough kernel/AppArmor: recent AppArmor
  versions add a per-profile `userns` permission item that lets a
  confined profile use unprivileged userns *with the sysctl left
  on*; the version to check on the target is unconfirmed (the
  item would go in the `apse` profile — see §2.1 for why B is
  the userns creator). Leaving the sysctl off (the CI way) is the
  simpler first test; the `userns` item is the more conservative
  end state.
- **Load:** `apparmor-parser -W /etc/apparmor.d/apse` +
  `systemctl restart apparmor`; verify with `aa-status`. No
  relabel — the path match arms the transition automatically.
- **Compositor:** sway is in Ubuntu's repos (wlroots → the
  staging global works); KWin also implements
  `wp_security_context_manager_v1` independently (first shipped
  in Plasma 6.0), so an Ubuntu/KDE setup would test both a
  different LSM *and* a second, non-wlroots protocol
  implementation. (GNOME/mutter has no implementation at all —
  its privileged operations ride on D-Bus-originated connections,
  so it is not a target.)

## 6. Ordering and how to resume

Priority: the **Fedora KDE VM tests the SELinux path against an
independent protocol implementation** (KWin) — the more valuable
data point of the two. The AppArmor work follows, on an Ubuntu
(24.04/26.04) VM with sway or KWin.

Resume checklist (in order):

1. **Baseline:** the userns sysctl, then `cargo test --locked --
   --test-threads=1` — expected green as-is (this is the CI
   configuration, plus a live compositor for the tagged tests).
   No code changes should be needed to get here.
2. **Confirm the AA state:** `aa-status`, and read
   `/proc/self/attr/apparmor/current` from a test process to fix
   the detection string format the `Apparmor` backend will match
   against (the mode suffix differs between profile formats).
3. **The §2.2 probe:** a throwaway binary that arms
   `change_profile` to a nested child profile, execs, and reports
   `prctl(PR_GET_PDEATHSIG)` — the answer decides whether the
   run-pipeline shim builds under AA.
4. **Confirm the nested-profile transition** fires at all on the
   target kernel/AA version (the in-file nesting should be the
   version-independent path; the separately-loaded
   "child profile" feature is the one with unconfirmed version
   requirements).
5. **Write the profiles** in `apparmor/`, then run the
   audit-driven tuning loop the SELinux module went through
   (expect the same silent-degradation class: the fontconfig
   `open`-before-`getdents` trap, the `SCM_RIGHTS` receive
   grants, the `MS_NODEV` devpts details, LESSONS #34-36).
6. **Document** the layer's honest scope in `apparmor/README.md`
   and add the AGENTS.md layout/Facts entries the way phase 8.2
   did for `selinux/`.
