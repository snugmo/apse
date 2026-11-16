# Adding build toolchains to the sandbox (no host root) — design sketch

Status: **exploration / feasibility** (written 2026-11-14; revised
2026-11-15 — §10 pins the definition contract). Fedora 45 target —
unprivileged user (uid 1000, `unconfined_t`), kernel
`7.3.3-300.fc45.x86_64`, `/` + `/home` + `/var` on one btrfs volume
(`/dev/vda3`), `/tmp` on tmpfs, `dnf5` 5.4.7, `rpm2cpio`/`cpio` present,
glibc 2.44. No code or profile changes yet. **The recommendation is §3:
a scoped overlay on `/usr` (+ `/etc`) over a shared, curated
extracted-RPM store** — ostree-motivated (measured: 2233 packages under
`/usr`, 409 under `/etc`, 13 under `/boot`, **zero** under `/var` and
`/opt`), verified mountable and write-safe on this kernel. The
separate-prefix variant is the fallback (§4.2); full-`/` stays rejected
(§4.1); `/var` gaps close per set with a tmpfiles manifest (§3.4); a
`dnf`-managed installroot mutated from *inside* the sandbox is the
opt-in power-user variant (§3.5); §9 relates this to the container
ecosystem (reuse boundary, OCI as transport). **§10 pins the definition
contract** (2026-11-15): a toolchain is *defined* by a user build script
or Dockerfile, built by `buildah` over the release base image, and
mounted read-only — the §3.1 set table survives only as the pure-RPM
reference case.

The question: how does a sandboxed app get **build tools** (compilers,
`make`, …) **not installed on the host** (no `dnf install`/root) while
keeping its existing isolation (namespaces, rebuilt rootfs,
landlock/seccomp, private home, the SELinux module)?

## 1. Feasibility findings (all verified this session)

1. **Unprivileged extraction works, end to end.** `dnf5 download
   --resolve --destdir <dir>
   <pkg>` fetches the RPM as a plain user; `rpm2cpio <rpm> | cpio -idm` unpacks it into a
   user-owned tree with the standard layout (`/usr/bin`, `/usr/lib`,
   `/usr/libexec`, …); the extracted binaries run — `make` 4.4.1 and
   `gcc` 16.2.1 execute straight out of the tree.

2. **`--resolve` yields the *minimal delta* against the host, not the
   full closure.** Downloading `gcc` fetched exactly one RPM (43 MB) —
   binutils/libgcc/glibc-devel were already on the host. That is the
   behaviour we want (small, no redundant glibc) — but see the catch in
   #3.

3. **RPM-level dependency resolution does *not* produce a functional
   toolchain.** `gcc` contains the *driver* and
   `collect2`/`lto-wrapper`/`lto1`, but **`cc1` — the C compiler proper
   — is packaged in `cpp` on F45** (`rpm -qf
   /usr/libexec/gcc/x86_64-redhat-linux/16/cc1` → `cpp-16.2.1-3.fc45`);
   the driver locates `cc1` by *path* (its `-print-search-dirs`
   `programs:` list), never via an RPM `Provides`/`Requires`, so `dnf5
   download --resolve gcc` fails at compile time with `cannot execute
   'cc1': posix_spawnp: No such file`, while adding `cpp` makes
   compilation succeed. **A toolchain's package set must therefore be
   curated, not derived from one tool name** — the real maintenance cost
   (a curation problem, not a mount/plumbing one).

4. **There is no library mixing in the same-release case.** The
   extracted F45 tree contains **no** glibc and no `libstdc++` (`find
   <tree> -name 'libc.so*' -o -name 'libstdc++*'` is empty); a program
   compiled with it links the **host**'s `/lib64` (`ldd`: `libc.so.6 =>
   /lib64/libc.so.6`, `/lib64/ld-linux-x86-64.so.2`). The sandbox's
   rootfs *is* the host's (the self-bind of `/`), so exactly one glibc
   is in play; the mixing risk is **real only for packages from a
   different release than the host** (§4.3).

5. **The extracted tree is relocatable for its own operation.** `gcc
   -print-search-dirs` resolves its internal dirs relative to the
   binary's own location (`-iprefix` = `<tree>/usr/lib/gcc/…`), so a
   tree bound to *any* prefix finds its own `cc1`/`collect2`/headers —
   verified: a tree bind-mounted to a scratch prefix compiles and links
   the host `/lib64`.

6. **Extraction gives a uniform SELinux label, not per-file labels.**
   `cpio` stamps every extracted file with the extraction dir's label
   (`user_tmp_t:s0` under `/var/tmp`, `user_home_t` under the home); the
   RPMs' original per-file labels are not restored (LESSONS #57: on 7.2
   `filecon` does not label created inodes). In confined mode this is
   *simpler*: one label covers the whole tree, so the module needs
   execute/read grants on a single type (§6).

7. **Full-`/` overlay is rejected; the scoped `/usr`/`/etc` overlay is
   not — and works, with upper.**
   - Overlaying onto `/` with `/` as a lower is self-referential and
     rejected; the workaround (rbind `/` to scratch, then overlay the
     tree + the rbind as lowers) also fails `ovl_validate`'s loop
     detection: on a single-root-filesystem system (`/`, `/home`, `/var`
     one btrfs) the root lower necessarily contains both. Fundamental,
     not a bug.
   - **Scoped variant (the ostree-motivated one):** lower = a *bind of
     the target subtree* (`/usr` or `/etc`) at an unrelated scratch
     path, upper = the extracted store — the containment check compares
     *real* paths, and shared underlying inodes are fine. Verified on
     this kernel in the exact apse sequence (single
     `unshare(CLONE_NEWUSER|CLONE_NEWNS)`, single-extent `1000→1000`
     map, `rbind /` first): on `/usr` (with and without the rbind
     context) added files appear and run, uppers **shadow** lowers (a
     fake `/usr/bin/rpm` replaces the real one), lowers stay intact
     (`libc.so.6` keeps its ELF magic, `dnf5` still executable), and the
     usrmerge symlinks (`/bin`, `/lib`, `/lib64`, `/sbin`) resolve
     *through* (`/bin/<new-tool>` works); on `/etc` shadow (`motd`),
     addition (`profile.d/…`), and pass-through (`os-release`) are all
     correct, and a **single-file bind stacked on top** (the step-7.5
     `hosts`/`hostname` pattern) still wins — the per-instance identity
     files remain the last word. Plain-directory and **tmpfs upper**
     variants mount fine too.
   - Correction to an earlier session (which reported *all*
     overlay-with-upper variants as failing, including tmpfs upper):
     re-run in a harness faithful to apse's namespace creation, **all
     succeed** — a harness artifact (finding #8), not a kernel limit.

8. **Unprivileged `mount(2)` in a self-created user+mount ns works
   *before* `execve` and fails *after* it (single-extent non-root map);
   never use `unshare(1)` for probe harnesses.** Decisive A/B on this
   kernel: one process, one `unshare(CLONE_NEWUSER|CLONE_NEWNS)`, the
   map written directly by that process — `rbind / → /` **succeeds**
   before `execve`; the identical operation after `execve` into bash
   returns EPERM ("must be superuser to use mount"); same SELinux
   context both sides (no transition, no AVC). (a) **apse is immune by
   construction** — A (the ns creator, never exec'd) does all rootfs
   steps, B (a fork) mounts `/proc` before its own exec; nothing in the
   pipeline mounts after `execve`. (b) **`unshare(1)`-based probes are
   untrustworthy here**: it always `exec`s (with the setuid-root
   `newuidmap`/`newgidmap` map writers), so a single-extent non-root
   harness lands post-exec and gets EPERM on *every* mount — including
   `mount --bind` — producing #7's earlier false negative. Write probes
   as python/ctypes: one `unshare(2)` call, direct
   `setgroups`/`uid_map`/`gid_map` writes, all mounts before any exec (a
   forked child's pre-exec mount works too — that is B).

9. **The overlay's write paths are exactly the ones the existing
   Landlock floor already denies (the shared store stays clean).** Raw
   namespace, no floor: (a) creating a *new* file under a root-owned
   lower dir **succeeds — it lands in the upper** (store creation never
   touches the lower); (b) appending to a *root-owned* lower file is
   EPERM (in-ns 0 is unmapped → root-owned inodes are the overflow uid)
   → **no copy-up**; (c) writing an *upper* file (owner 1000) **reaches
   the store on the host** (verified: the host-side copy gained the
   appended byte). In apse, `BASE_READ` grants `/usr` and `/etc`
   **read-only**, so all three are denied before the overlay: no
   copy-up, no store mutation, **zero new app permissions** — the store
   is effectively immutable to the app (§3.3).

10. **The `/var` gap closes with `systemd-tmpfiles` offline mode.**
    `systemd-tmpfiles --create --root=DIR --prefix=/var` run as a plain
    user against a user-owned scratch root materializes exactly the
    declared tree (verified on F45: `d` lines with numeric owners build
    `/var/lib/…`, `/var/log/…` at the requested modes, exit 0). Two
    gotchas: (a) with `--root=`, confs are searched at
    `<root>/etc/tmpfiles.d` and `<root>/usr/lib/tmpfiles.d` — **not**
    `<root>/tmpfiles.d` (a conf there is silently ignored); (b) user
    *names* in the conf must resolve on the host, else the line fails
    (exit 65, nothing created) — a normalized conf with numeric owners
    (the app's real uid) sidesteps this and is what we want anyway
    (in-ns 0 is unmapped; the state dirs must be the app's to write).
    The core toolchain set (gcc, cpp, make, binutils, gdb, dnf5,
    p11-kit, ca-certificates, glibc) declares **nothing** under `/var`
    (verified with `rpm -qL`) — hence §3.4's opt-in per-set manifest.

11. **`dnf install` on top of the host's installed state works — but
    only inside the sandbox, and the "database copy" lives in `/usr`,
    not `/var`.** On this (ostree-laid-out) F45, the rpm ndb is
    `rpmdb.sqlite` at **`/usr/lib/sysimage/rpm`**, `/var/lib/rpm` being
    just a **symlink** to it. Verified: (a) a user-owned installroot
    (reflink-copied `/usr` — which carries the db — plus a
    `/var/lib/rpm` symlink recreated inside the root) seeded with the
    host's db shows the full host state (`rpm -qa` → 2694 packages); (b)
    `dnf5 --installroot=<root>` as a plain user **runs through resolve
    and download** (minimal delta: `unifdef` → one 37 KiB RPM) and dies
    only at the transaction: **the rpm backend `chroot()`s into the
    installroot, and a plain user on this host (CapEff=0) cannot
    `chroot`** ("Unable to change root directory: Operation not
    permitted") — so the *host-side* `dnf --installroot`/`rpm --root`
    recipe is out on a no-capability user; (c) inside a self-created
    user ns (apse's exact A/B construction), the `chroot` **succeeds**,
    and `rpm -qa --root=/` run from inside it reads the seeded db
    through the symlink (2694). Consequence: "dnf install in the
    overlay" is *in-sandbox* (the capability context that makes the
    chroot legal), and the db copy goes into the store's `usr/` — the
    overlay upper, at the exact path the app's rpm reaches via the
    symlink (§3.5).

## 2. Where a toolchain can live (the visibility constraint)

The private-home design (decisions #43/#44) shapes everything: the app's
`$HOME` is a **private per-app state tree** that *replaces* the real
home, and `/var`, `/srv`, `/opt/*`, `/boot`, `/media`, `/mnt` are
masked. So the only user-writable, persistent, *visible* space inside
the sandbox is the per-app state tree (the app's `$HOME` and its XDG
dirs) and the fresh `/tmp`. A store under the **real** home
(`~/.local/share/…`) is **hidden behind the home bind** — its path
resolves *after* the home is replaced, so a later `rw_bind` of it is a
no-op self-bind onto the stand-in (decision #28's trap, one level up);
`/var/tmp` (where the rootfs scratch lives) is masked.

The mechanism that already solves this is the **step-1 carry**: a
**bind** of a host path into the scratch dir (`mount(real_path →
scratch/…, MS_BIND)` — a plain bind shares the dentry tree, so it is
**zero-copy**; the same pattern the per-instance runtime dir and the
per-app state tree use). It happens in step 1, *before* the home is
replaced in step 7, so it reaches the real store: for the overlay design
the carried dir *is* the upper (per-instance workdir in scratch next to
it); for the fallback, a step-7 bind exposes it as a prefix. Two binds,
no data movement, #28-safe ordering — the store needs no new plumbing,
only to be *named* and *curated*.

## 3. Recommended shape: scoped `/usr` (+ `/etc`) overlay over a shared, curated store

### 3.1 Fetch & store (user side, no root)

> **Superseded as the definition surface (2026-11-15, §10).** A
> toolchain is now *defined*
> by a user build script (or Dockerfile); the set→packages table is no
> longer the
> maintenance surface — it simply becomes *what the script installs*.
> The extraction
> mechanics below stay valid for any script that wants them.

A stable user-owned store, e.g. `$XDG_DATA_HOME/apse/toolchains/<set>/`,
with `usr/` and `etc/` subtrees, produced by `dnf5 download --resolve
--destdir` per package + `rpm2cpio | cpio -idm` into the tree (the
extraction keeps the standard layout, so the store's `usr/` is exactly
the files the packages would install under `/usr`). Because of finding
#3, the unit of installation is a **curated set**, not a single tool
name (e.g. a `gcc` set = {`gcc`, `cpp`, `gcc-c++`, `binutils`,
`glibc-devel`, …}); the set definition (set → packages) is the
maintenance surface — a small table kept in sync with the release,
extensible by the user. Sets are **immutable once built** (a new set = a
new directory, the ostree deployment pattern); a profile references a
set by name.

### 3.2 Build wiring (apse side) — one new rootfs step between 2 and 3

> **Runtime revision (2026-11-15, §10.4):** the target shape is the
> single read-only
> overlay over the whole self-bound root; this section's two-target
> shape stands as the
> verified fallback.

For a run whose profile selects set `N` (a new profile field, e.g.
`toolchain = "gcc"`), the run does:
- **new step 2.5** (after the step-2 self-bind, before 7.5): for each
  target the set populates (`/usr` and `/etc`): `bind <ns>/usr →
  scratch/tc/lower/usr` (likewise `etc`); `mkdir
  scratch/tc/work/<N>-<instance>` (fresh per instance, on the **same
  real filesystem** as the upper — on this target `/` and `/home` are
  one btrfs, so scratch and the home-side store both qualify; on a
  multi-volume host the workdir must live *inside the store tree*);
  `mount -t overlay -o
  lowerdir=scratch/tc/lower/usr,upperdir=scratch/tc/<N>/usr,workdir=…
  /usr` (likewise `/etc`).
- **step 7.5 is unchanged**: the per-instance `/etc/hosts`/`hostname`
  binds stack *on top of* the `/etc` overlay (later mount wins at that
  path — verified), so the identity files are still the last word.
- **steps 8–9 (masks, chroot) unchanged**: `/usr` and `/etc` are not
  masked; the `/var` mask hides the scratch (store + workdirs) from the
  app, which sees the set's files **only** through the `/usr`/`/etc`
  overlay — exactly like natively installed packages.
- **teardown**: no explicit umounts — the mount namespace dies with the
  process; the workdirs die with the scratch.

No environment surgery is needed: `gcc` lands at `/usr/bin/gcc`, `cc1`
at its standard path (finding #5), the usrmerge symlinks resolve through
the overlay (verified), and the profile's `[env]` remains if a set ever
wants one.

### 3.3 Why the shared store stays safe

Finding #9: every write path the overlay offers is a *write*, and the
existing **read-only** Landlock grants on `/usr`/`/etc` deny all of them
in B (in confined mode, the label rules deny them too, §6). Copy-up is
therefore unreachable, the store is effectively read-only to the app,
and concurrent instances sharing a store share an *immutable source*.
The per-instance workdir (step 2.5) keeps the one remaining hazard —
concurrent copy-ups *racing* inside a shared workdir — out of the
equation; the kernel does not reject a shared workdir (observed), so
this is hygiene, not a hard requirement.

### 3.4 The `/var` gap — a tmpfiles manifest per set (no overlay)

Some packages expect state dirs under `/var`. The ostree answer —
packages ship `/usr/lib/tmpfiles.d/*.conf` declarations and the `/var`
volume is built from them — is what we want (finding #10). Opt-in per
set: the core toolchain set declares nothing under `/var`, so most sets
need no manifest. A set that does carries a **normalized** tmpfiles conf
(`d` lines; numeric owners = the app's real uid — the host may not have
the users the packages name, and in the sandbox the dirs must be the
app's to write):

- **step 1 (host side, scratch):** stage the conf at
  `<scratch>/varroot/usr/lib/tmpfiles.d/` (the `--root=` search path —
  `<root>/tmpfiles.d` is *not* one) and run `systemd-tmpfiles --create
  --root=<scratch>/varroot --prefix=/var`; the whole `/var` tree is
  materialized in scratch — a **carry** (bind, not copy), the §3.2
  step-1 shape.
- **step 8 (masks):** the `/var` mask becomes a **bind of
  `<scratch>/varroot/var`** instead of the empty tmpfs (`/var` dropped
  from the mask list for that run). The app sees exactly the declared
  tree and nothing else, all app-owned; the rest of the host `/var`
  (including the rootfs scratch) stays hidden.
- **grants:** the existing `rw_binds`-style `allow_path` grants cover
  the subdirs the app may write; the manifest marks which, default
  read-only (the `BASE_READ` posture).
- **lifetime:** ephemeral by default — the tree lives under the
  per-instance scratch and dies with the run (the "rebuilt, not masked"
  pattern). A set that needs *persistent* `/var` state binds those
  specific dirs into the per-app state tree (the §3.2 carry, as the home
  does) — one line in the manifest.

This is deliberately **not** a third overlay target: `/var` content is
*state*, not *distribution* — a fresh tree per run is the ostree
semantics, and it keeps `/usr`/`/etc` the only distribution surface.

### 3.5 Variant: a `dnf`-managed installroot (opt-in per set, in-sandbox)

Finding #11 shows the atomic-OS end-state of this feature: a set *is* an
**installroot** — an ostree-style deployment in a user directory — that
the user's `dnf` mutates *from inside the sandbox*:

- **the set = a full installroot**: `/usr` (reflink clone of the host's
  — which carries the db at `usr/lib/sysimage/rpm`), a **full `/etc`
  shadow** (reflink; rpm's config-file operations must hit upper files,
  not copy-up-EPERM on root-owned lowers), the `/var/lib/rpm` symlink,
  the §3.4 tmpfiles tree — ~13 GB apparent / near-zero real (btrfs
  reflink) until written.
- **the run**: a profile flag (e.g. `dnf = true`) makes apse grant
  **`ReadWrite` on the `/usr`/`/etc` overlay paths and the `/var` tree**
  for that one run (a new, explicitly opt-in grant class — the default
  set stays read-only, §3.3). Inside, the user just runs `dnf5 install
  <pkg>` (or `rpm -Uvh …`): the default installroot *is* the sandbox's
  `/`, the chroot is legal (the sandbox is a self-owned userns, finding
  #11c), and the transaction's writes and the **db update land in the
  overlay upper** — the set evolves across runs.
- **upgrades**: with the full `/usr` shadow, *upgrades of host packages*
  work too (every path is an upper file; the root-owned lower is never
  touched). Without the shadow, only *new* installs work (finding #9:
  unlinks of root-owned lower files EPERM).
- **integrity**: a half-finished transaction can corrupt the set — the
  ostree answer, adopted: a directory of **deployments**
  (`<store>/sets/<N>/`), the profile points at the last-known-good, a
  failed run leaves the previous intact. Single-writer per set (a
  personal single-user machine; a lockfile if two runs share one).
- **what it is not**: a *superset* of §3.1, not a replacement — the
  cpio-extracted immutable set stays the default shared-store baseline
  (zero new permissions, safe to share across instances); the
  dnf-managed installroot is the power-user mode for sets the user wants
  to extend live.

## 4. Alternatives considered

### 4.1 Full-`/` overlay — **rejected**

Mount an overlay with the extracted tree as an added lower over the
system root, so `gcc` appears "natively installed" at `/usr/bin/gcc`.
Not practical on a single-root-filesystem system (finding #7) — the
mount itself is easy; the self-nesting is the wall — and scoping to
`/usr`/`/etc` sidesteps it. Making it work would require the host root
on a *separate* filesystem (loop device, dedicated volume) — ongoing
complexity for a convenience §3 already provides.

### 4.2 Separate prefix (the original recommendation) — fallback

The extracted tree exposed as a stable in-sandbox prefix via the same
carry (steps 1 + 7), wired with `[env]` `PATH`/`LD_LIBRARY_PATH`
prepending. Simpler than §3 (no overlay mount, no workdir, no `/etc`
interaction) and robust where the scoped overlay misbehaves; costs: the
environment surgery, non-default library paths, and weaker "natively
installed" semantics (`<prefix>/usr/bin/gcc` instead of `/usr/bin/gcc`).
Keep as the fallback — the carry and env plumbing are identical to §3's,
so switching is a profile-value change, not a rework.

### 4.3 Self-contained sysroot (cross-release) — optional escape hatch

`dnf5 download --alldeps` (the **full** closure, glibc included) into a
tree, and build with `--sysroot=<tree>` so the artifact links the tree's
own glibc instead of the host's. This eliminates mixing *entirely*; the
correct tool for a toolchain from a **different release than the host**,
at the cost of size (hundreds of MB) and a build-flag convention. Keep
as a documented advanced option — the default (§3) is release-pinned and
needs none of this.

## 5. The "library mixing" question, resolved

- **Same release as the host (the default):** no mixing is possible —
  the extracted tree has no glibc/libstdc++ of its own (finding #4), a
  single host glibc is in play, artifacts link it, and the overlay does
  not change this. Safe by construction, not by care.
- **Different release than the host:** mixing *is* a real risk (two
  glibcs, incompatible ABIs). The answer is §4.3 (sysroot) or, more
  simply, **pinning toolchains to the host's release** as the default
  policy and documenting the sysroot escape hatch for the rest.

## 6. Confined mode (SELinux)

- The store keeps its **uniform** label (finding #6): `user_home_t`
  under the home (`$XDG_DATA_HOME/apse/toolchains/…`). The app reaches
  those inodes **only** through the `/usr`/`/etc` overlay paths, and the
  app's existing home grants (decision #43: the full file lifecycle on
  the state tree, including execute) probably already cover read/execute
  of `user_home_t` — to be confirmed with a zero-denial run (the
  standard tuning loop). `cc1`/`collect2` are exec'd by the driver as
  **same-domain children** of the app (no new transition).
- The genuinely new surface is `apse_t` (process A) doing the overlay
  **`mount(2)`**: expect one `mountpoint`/fstype-related allow (the
  overlay fstype's context against the `usr_t`/`etc_t` targets), plus
  whatever label the overlay **superblock** ends up with (the upper's
  genfs context — `user_home_t` here — is the likely answer, which the
  app is already allowed to read). One or two new lines in
  `selinux/apse.cil`, same shape as the v2.14 gap classes.
- The per-instance `/etc` files (`apse_etc_t`, step 7.5) are bound on
  top of the overlay — the existing read-only rule carries over
  unchanged (verified the stacking in the unconfined probe).
- The `/var` tree (§3.4) is built in scratch (`/var/tmp`), so its inodes
  take scratch's label (`user_tmp_t`) uniformly, like every other built
  dir — the app's grants on that type (the state-tree lifecycle) cover
  read/write of the declared dirs. The one new surface: `apse_t` (A)
  *exec'ing* `/usr/bin/systemd-tmpfiles` — whether that transition can
  still write the scratch tree (or needs a `typetransition`/grant) is a
  tuning-loop question (the v2.14/v2.32 class); if messy, fallback: A
  `mkdir`/`chmod`s the declared dirs directly (the conf format is
  trivially parseable; the sets don't use tmpfiles' other line types).
- The §3.5 dnf variant adds the largest new surface of all: the app
  execs `dnf5`/`rpm` (and whatever they exec) **and writes the store
  type** — the module would need the app's file-lifecycle grants on the
  store label to cover the transaction (create/unlink/rename across
  `usr/`, `etc/`, the db) plus `process { chroot }` (seccomp side
  already open: step 9 chroots). Expect a tuning loop, as for every
  other exec-world expansion (v2.32).

## 7. Landlock

- **No new grants for the overlay design.** `BASE_READ` already grants
  `Read` on `/` and `/usr` (and `/etc`); the grants are on *paths*, so
  after step 2.5 they resolve to the overlay mount, whose root dentry
  (the upper's root inode) sits in the dentry chain of *every* path
  under `/usr` — lower-origin and upper-origin alike — and one `Read`
  grant covers the whole merged view (what §3.3 needs). The step-7.5
  `allow_file` grants on `/etc/hosts`/`hostname` are created in B
  *after* the overlay exists, so they bind to the scratch inode of the
  stacked single-file bind — unchanged.
- (The §4.2 fallback, if ever used, needs the `ro_binds`/ancestor-grant
  treatment instead: `Read` on the prefix, plus `ReadWrite` on any
  tool-writable subdirectory.)
- **The §3.5 dnf variant needs a new, opt-in grant class**: `Read`
  **plus `Write` on `/usr` and `/etc`** (the overlay paths — the same
  path-grant logic applies, the merged view becomes writable) and
  `Read+Write` on the declared `/var` tree. This is the one place the
  "store is immutable" invariant (§3.3) is deliberately broken, so it
  must be explicit in the profile (`dnf = true` or similar), never a
  default, and a set that takes it is a *deployment*, not a shared
  source.

## 8. Open questions

1. **Store location.** Home-side (hidden behind the home bind, carried
   in step 1) vs. non-home. The workdir constraint (same real filesystem
   as the upper) is satisfied on this target by scratch (`/` and `/home`
   are one btrfs), and dissolves in the §10.4 no-upper shape. —
   *Resolved by §10.3 (2026-11-15): the store lives in the §28 scratch.*
2. **CLI surface.** A first-class `apse toolchain` subcommand
   (list/add/remove, driving `dnf5 download` + extraction; sets
   immutable) vs. a profile field plus a hand-run `dnf5` recipe. —
   *Resolved by §10.3 (2026-11-15): `apse toolchain build/list/rm`,
   building from a script/Dockerfile.*
3. **Curation ownership.** Who maintains the set→packages table and
   keeps it in sync across releases — checked-in manifest vs. per-user
   manifests? The real maintenance cost (finding
   #3) — and for §3.5 dnf sets it mostly evaporates (dnf resolves the closure; the "set" is
   its initial package list plus the release pin, growing on demand
   in-sandbox). — *Resolved by §10.1 (2026-11-15): the table is replaced
   by the user's definition script.*
4. **`/opt`.** Zero packages install there on this (ostree-laid-out)
   system, so the targets are only `/usr` + `/etc`; a set shipping
   `/opt` content would unmask via a profile `ro_bind` and add a third
   target — the pattern is identical. (`/var` is closed, not open:
   §3.4.) — *Resolved by §10.4 (2026-11-15): the whole-root shape
   shadows any prefix a toolchain ships automatically.*
5. **Release-pinning policy.** Default toolchains to the host's release
   (no mixing, §5); document the sysroot escape hatch (§4.3) for
   cross-release needs.

## 9. Relation to the container ecosystem (still under investigation)

This feature touches a crowded corner of the Linux ecosystem (container
runtimes, image builders, OCI); where apse sits relative to it is
recorded here. **Nothing here is set in stone:** the feature is still
being investigated — this is current thinking, not an architecture.

### 9.1 We are not reimplementing podman/docker — and not trying

The structural difference is that **apse keeps the host's root
filesystem as the base of the sandbox; container runtimes replace it.**
Everything else follows from that one fact:

- The app runs as its *real* uid with in-ns `0` **unmapped** (decisions
  #9/#10). A container maps `0→0` (the workload *is* root inside its
  namespace); the apse app can never be root — which is precisely what
  makes the overlay design (§3) work: the "root-owned" lower is just a
  uid-1000 file the app cannot write, and there is nothing else to
  defend.
- The product is **one known desktop app**, not N generic workloads. The
  desktop-socket half (tagged `wp_security_context_v1` socket,
  compositor consent prompt, selection allowlist, clipboard gate) is the
  actual reason apse exists; no container tool does it.
- The closest shape-relatives are therefore **rpm-ostree and the nix
  store**, not docker: an immutable, user-managed, `/usr`-centric
  filesystem layer with deployment-style integrity semantics, *over an
  existing host*. apse borrows that shape — the extracted-package store,
  the read-only merge (§3.2), the dnf-managed installroot as a
  "deployment" in a user directory (§3.5) — and none of the code
  (neither ostree nor nix is on this host, and neither is a fit for the
  in-process runtime).

### 9.2 Reuse: the user-side build/distribution layer only

Boundary rule: **the apse runtime stays 100% custom** — the in-process
sandbox *is* the product. What is borrowed is the **user-side
build/distribution layer**: tools that run on the host as the user to
*produce* a store, which **apse never links, spawns, or depends on at
runtime**; apse consumes an already-built directory (or a tarball of
one) and nothing else.

| Component (this host) | Use for | Notes |
|---|---|---|
| `skopeo` 1.24.1 | Fetcher for the §3.1 download step: pulls a toolchain image from a registry (`docker://`) into a local dir layout | `skopeo copy docker://… dir:<store>/<N>`; the output is a plain directory, which is all apse sees |
| `buildah` 1.45.1 / `podman` 6.1.3 | Builder for the compose step: a plain `Dockerfile`/buildah build runs `dnf`/`rpm` inside *their own* unprivileged userns and produces the store | Runs on the host, as the user, with no apse involvement; this is the host-side analogue of what §3.5 does in-sandbox |
| `umoci` *(not installed yet)* | Pack/unpack between the OCI layout and a user tree — the §3.5 round-trip: a dnf-mutated installroot → re-packaged as an image | Optional; a plain `cp -a` of the store directory is the minimum substitute |
| `cosign`/sigstore *(not installed yet)* | Optional: sign the store tarball/image for distribution | Purely distribution-side; apse never verifies anything |
| `fuse-overlayfs` *(installed)* | Fallback for the workdir constraint (open #1): if the upper and workdir cannot share a real filesystem on a multi-volume host, fuse-overlayfs does not care | Open: where the FUSE server would run (it is another process inside the ns and needs its own grants) — not settled |
| `runc`, `crun`, `bwrap` | **Not reusable** | Different process model: they build a namespace for arbitrary container workloads from scratch. apse's in-process sandbox — rebuilt rootfs, single-extent uid map, tagged socket, the supervisor — is the product and is already written |
| `rpm-ostree`, `nix` | **Concept only** | The shape is borrowed (immutable `/usr` store, deployments, content-addressed layers); no code reuse |

### 9.3 OCI images: transport yes, runtime no

Use the OCI image format **only as the packaging/distribution format**
for toolchain stores. apse never sees OCI: at runtime it sees a plain
directory (the store), and the overlay mount (§3.2) does not care how
that directory was produced.

- **Store shape.** One **base image per release** (the shared `/usr`
  shadow carrying the rpm db, the full `/etc` shadow, the `/var/lib/rpm`
  symlink, the tmpfiles tree — the §3.5 seed, ~13 GB apparent /
  near-zero real on btrfs) plus **small delta layers per set**
  (extracted RPMs, §3.1) — exactly the container world's base-image +
  app-layer model: every set on a release shares one base.
- **Build path A (host-side).** `buildah`/Dockerfile runs the dnf/rpm
  compose step in its own unprivileged sandbox; `skopeo copy` to dir (or
  `umoci unpack`) yields the store directory. Best fit for the
  *curation* side (checked-in manifests, CI, registry distribution).
- **Build path B (in-sandbox, §3.5).** A dnf-mutated installroot is
  packed back out — "evolve the set from inside the sandbox" and
  "redistribute the set" become one feature.
- **What we deliberately refuse to absorb.** No OCI *runtime*
  (runc/crun). No *layer-mounting inside the sandbox* — the store is a
  **flattened** directory (one overlay upper, one mount, not a stack of
  N layer mounts). No image *config semantics* (entrypoint, env, labels,
  user have no meaning for a toolchain store; the profile TOML is that
  layer).
- **Minimum viable input.** A tarball of the store directory — or the
  directory itself. OCI is a nicer transport (registry, signatures,
  cross-machine), not a precondition.

## 10. Toolchain definition: the build contract (pinned 2026-11-15)

§3 pins *where* a toolchain lives (a scoped overlay over the live
rootfs) but left *how its content is defined* to a curated set→packages
table (§3.1) — the feature's real maintenance cost (finding #3),
assuming an RPM world. **The definition is now a build contract:** a
toolchain is defined by a user **build script** (or a Dockerfile),
executed against the **release base image** by `buildah`, producing an
OCI image whose expanded root is what the sandbox overlays. The table
evaporates: the script *is* the curation, and it may use any package
manager, any download, any custom construct — the rpm-ostree-style
"overlay RPMs on the base OS" is one of its many forms, not its
definition.

### 10.1 The contract

A toolchain is a triple — **(definition file, base image, arch)** —
whose build product is an **OCI image**:

- **The definition file** is one of two shapes:
  - a **shell script** — apse wraps it into a three-line Dockerfile and
    builds that:

    ```dockerfile
    FROM <base>
    COPY <script> /tmp/apse-build.sh
    RUN /bin/sh /tmp/apse-build.sh
    ```

  - a **Dockerfile** — built as-is. In either case the script's
    filesystem *is* the artifact: it installs into `/` however it likes
    — `dnf install` (the rpm-ostree case), `apt`/`pacman` (non-RPM
    bases), `curl | tar` binary drops, `rustup`/`cargo` bootstraps,
    hand-placed files, patches, generated configs. The only requirement
    is that it runs in a root shell of an unprivileged chroot — what
    `buildah --isolation chroot` executes.
- **The base image** is **one per release**: the host OS root in OCI
  form (§9.3's per-release base — the same `/usr` layout as the live
  system, so the paths in the built layer align with what the runtime
  overlays onto). Produced once per release by the same machinery (a dnf
  root or a packed live `/` — §9.3 build path B). A definition that
  wants dnf to resolve a closure gets it from the base (the rpm db
  travels with the image, §3.5).
- **The output** is an OCI **dir** image in the apse store plus its
  **expanded root** (`umoci unpack` → a single flat directory). The
  expanded root is what the sandbox mounts (§10.4); OCI is transport
  only, exactly as §9.3 rules.

### 10.2 The builder: `buildah bud`, unprivileged, build-time

One builder for both definition shapes: `buildah bud --isolation chroot`
run as the user (`--network` gated: on by default — the point is
downloading; `none` for the offline / dnf-cache case). `chroot`
isolation is a child userns + chroot — no kernel mount features
required, so the build works on any host, and the script's reach ends at
the build root (a hostile or broken script can do anything to a
throwaway tree, nothing to the host); it sits exactly on the §9.2 reuse
line (host-side, user-run, never spawned or linked by apse).

Build-time rather than runtime, for four reasons:

- **build once, use many** — the cache key is `sha256(definition bytes ‖
  base digest ‖ arch)`; identical inputs never rebuild. A build runs
  into a scratch dir and the store entry is replaced only on success — a
  failed build leaves the previous artifact (the deployment-style
  integrity of §3.5);
- **no network at sandbox start** — the runtime path is a pure mount;
- **reproducible and signable** — the artifact is an OCI image (`cosign`
  sign/verify, §9.2), and a plain tarball of the expanded root remains
  the minimum viable input (§9.3);
- **no new trust boundary** — the build runs in the same class of
  unprivileged userns the sandbox itself uses.

### 10.3 Store, cache, CLI

- **Store:** `/var/tmp/.apse/toolchains/<name>/` (the §28 scratch
  convention — on `/var/tmp`, hidden from the sandbox by the `/var` mask
  and the landlock floor, mode 0700): the OCI dir image, the expanded
  root, and a `manifest` recording the name, definition hash, base
  digest, and arch.
- **Cache:** a run whose profile selects toolchain `N` (the new profile
  field, §3.2) resolves `N` in the store: a missing entry, or a
  definition-hash / base-digest mismatch, triggers a build; otherwise
  the existing expanded root is mounted as-is.
- **CLI:** `apse toolchain build <definition> [--name N] [--base B]
  [--network auto|host|none]`, `apse toolchain list`, `apse toolchain rm
  <name>`; the profile's `toolchain` field (a name, or a path — a path
  builds on demand); ad-hoc `run --toolchain
  <name>`. This resolves §8#2.

### 10.4 The runtime mount (step 2.5, revised)

The runtime consumer of a built toolchain is a **read-only overlay over
the live rootfs** — the rpm-ostree shape, mounted at the root instead of
per prefix:

    step 2:   self-bind /                     (the live OS, a mount we
    own) step 2.5: overlay over / lowerdir = <store>/N/root : / (the
    toolchain first, the live root second)

The toolchain's files **shadow** same-path live files (the earlier lower
wins); everything else — `/bin`, `/lib`, `/proc`, the home, the rest of
the live OS — **passes through** from the self-bound second lower, which
resolves at mount time to the step-2 self-bind — a mount *we* created,
not the original init-ns root (whose clone is the one unprivileged
operation this kernel rejects, LESSONS #83).

One mount, no `upperdir`, no `workdir`: the layer is immutable by
construction — nothing to copy up into, so the §3.3 copy-up hazard and
its per-instance workdir hygiene both dissolve (the store is shared
read-only across instances, §3.3) — and teardown has nothing to clean up
(the mount namespace dies with the process; the store entry stays).
Every later rootfs step mounts *on top of* the overlay, including the
step-7.5 `/etc/hosts`/`hostname` identity binds, which remain the last
word at their paths.

Compared with the §3.2 two-target shape (`/usr` + `/etc`), the
whole-root overlay also covers **`/opt`, `/usr/local`, and any other
prefix** a toolchain ships, with no extra machinery — §8#4 closes
itself.

**Verification status (7.3.3-300.fc45, this session):** a
*plain-directory* lower in `/var/tmp` works unprivileged in a
single-extent `1000:1000:1` userns (probed with upper+workdir; the
no-upper read-only view is the simpler case); a *bind-created* mount as
the sole lower works (the §3.2 scratch-bind shape; finding #8); **a
two-lower list whose second entry is the step-2 self-bind is the one
unverified form** — the known `lowerdir=/` EINVAL is about the
*original* init-ns root mount, and the self-bind is a different,
creator-owned object, but that exact shape has not been probed yet.
**Fallback, if it fails:** the verified §3.2 shape — per-target overlays
at `/usr` and `/etc`, lower = the scratch bind of the live target, upper
= the corresponding subtree of the toolchain root, per-instance workdir
in the scratch, read-only by the landlock grants — with `/opt` handled
by the §8#4 unmask + third target. The build contract (§10.1–10.3) is
identical in both cases; only the mount shape differs.

### 10.5 What this resolves

- **§3.1 (the set table):** superseded as the definition surface. The
  `dnf5 download` + `rpm2cpio` extraction survives as *a* reference
  definition (the pure-RPM case — a script that just runs it) and as the
  inner mechanics of §3.5.
- **§3.4 (the `/var` gap):** unchanged — it stacks on top of whatever
  the `/var` view is (the target shape, the fallback, or no toolchain at
  all).
- **§3.5 (dnf-managed installroot):** unchanged in role — the power-user
  mode for *live* evolution inside the sandbox (its write paths need an
  upperdir, which the §10.4 read-only shape deliberately lacks). A set
  evolved that way is re-packed out (§9.3 path B) and re-enters the
  system as an ordinary built artifact — the loop closes.
- **§8 open questions:** #1 (store location), #2 (CLI), #3 (curation),
  #4 (`/opt`) resolved as marked above; #5 (release pinning) stays open
  as written.
- **Security:** the build's containment is the child-userns chroot
  (§10.2); the runtime adds no new attack surface (the layer is part of
  the already-contained world, and the store sits behind the `/var` mask
  + landlock floor). Setuid binaries inside a toolchain are inert in the
  app for the namespace-level reasons of LESSONS #82 — a toolchain
  cannot grant what the uid map already denies.
