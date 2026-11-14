# Adding build toolchains to the sandbox (no host root) — design sketch

Status: **exploration / feasibility** (written and revised 2026-11-14,
same day). Every finding below was hands-on-verified this session on the
Fedora 45 target — unprivileged user (uid 1000, `unconfined_t`), kernel
`7.3.3-300.fc45.x86_64`, `/` + `/home` + `/var` on one btrfs volume
(`/dev/vda3`), `/tmp` on tmpfs, `dnf5` 5.4.7, `rpm2cpio`/`cpio` present,
glibc 2.44. No code or profile changes yet; this is the working sketch
to decide the feature's shape. **The recommendation is in §3: a scoped
overlay on `/usr` (+ `/etc`) over a shared, curated extracted-RPM
store** — the ostree-motivated proposal (most Fedora packages install
only under `/usr`, `/etc`, `/opt`; measured here: 2233 packages under
`/usr`, 409 under `/etc`, 13 under `/boot`, **zero** under `/var` and
`/opt`) is now verified mountable and write-safe on this kernel. The
separate-prefix variant survives as the fallback (§4.2); the full-`/`
overlay stays rejected (§4.1).

The question this documents: how does a sandboxed app get **build
tools** — compilers, `make`, and the like — that are **not installed on
the host**, i.e. without `dnf install` / root, while staying inside the
isolation we already have (namespaces + the rebuilt rootfs +
landlock/seccomp via nono, the private per-app home, and, in confined
mode, the SELinux module)?

## 1. Feasibility findings (all verified this session)

1. **Unprivileged extraction works, end to end.**
   `dnf5 download --resolve --destdir <dir> <pkg>` fetches the RPM as a
   plain user; `rpm2cpio <rpm> | cpio -idm` unpacks it into a
   user-owned tree with the standard layout (`/usr/bin`, `/usr/lib`,
   `/usr/libexec`, …). The extracted binaries run: `make` 4.4.1 and
   `gcc` 16.2.1 both execute straight out of the tree.

2. **`--resolve` yields the *minimal delta* against the host, not the
   full closure.** It downloads a package plus its dependencies that
   are *not already installed*. Downloading `gcc` fetched exactly one
   RPM (43 MB) because binutils/libgcc/glibc-devel were already on the
   host. That is the behaviour we want (small, no redundant glibc) —
   but see the catch in #3.

3. **RPM-level dependency resolution does *not* produce a functional
   toolchain.** The `gcc` package contains the *driver* and
   `collect2`/`lto-wrapper`/`lto1`, but **`cc1` — the C compiler
   proper — is packaged in `cpp` on F45** (`rpm -qf
   /usr/libexec/gcc/x86_64-redhat-linux/16/cc1` → `cpp-16.2.1-3.fc45`).
   The driver locates `cc1` by *path* (its `-print-search-dirs`
   `programs:` list), never via an RPM `Provides`/`Requires`, so
   `dnf5 download --resolve gcc` hands you a driver that fails at
   compile time with `cannot execute 'cc1': posix_spawnp: No such file`.
   Adding `cpp` to the tree makes compilation succeed. **Consequence:
   a toolchain's package set must be curated, not derived from one
   tool name.** This is the real "maintenance" cost the initial
   intuition was pointing at — it is a curation problem, not a
   mount/plumbing problem.

4. **There is no library mixing in the same-release case.** The
   extracted F45 toolchain tree contains **no** glibc and no
   `libstdc++` (verified: `find <tree> -name 'libc.so*' -o -name
   'libstdc++*'` is empty). A program compiled with it links the
   **host**'s `/lib64` (`ldd` on the artifact: `libc.so.6 =>
   /lib64/libc.so.6`, `/lib64/ld-linux-x86-64.so.2`). Because the
   sandbox's rootfs *is* the host's rootfs (the recursive self-bind of
   `/`), there is exactly one glibc in play — nothing to mix. The
   "mixing libraries with the host" risk the initial brief raised is
   **real only if the user pulls packages from a different release
   than the host** (§4.3 is the answer for that case).

5. **The extracted tree is relocatable for its own operation.**
   `gcc -print-search-dirs` resolves its internal dirs relative to the
   binary's own location (`-iprefix` = `<tree>/usr/lib/gcc/…`), so a
   tree bound to *any* prefix finds its own `cc1`/`collect2`/headers.
   Verified: a tree bind-mounted to a scratch prefix compiles a C file
   and links the host `/lib64`.

6. **Extraction gives a uniform SELinux label, not per-file labels.**
   `cpio` stamps every extracted file with the extraction dir's label
   (`user_tmp_t:s0` under `/var/tmp`, `user_home_t` under the home) —
   the RPMs' original per-file labels are not restored (LESSONS #57: on
   7.2 `filecon` does not label created inodes). In confined mode this
   is *simpler*, not worse: one label covers the whole tree, so the
   module needs execute/read grants on a single type (§6).

7. **Full-`/` overlay is rejected; the scoped `/usr`/`/etc` overlay is
   not — and works, with upper.**
   - Overlaying onto `/` with `/` as a lower is self-referential and
     rejected; the workaround (rbind `/` to scratch first, then overlay
     with the extracted tree + the rbind as lowers) is also rejected by
     overlayfs loop detection (`ovl_validate`): on a single-root
     filesystem system (here `/`, `/home`, `/var` are one btrfs) the
     root lower necessarily contains both. Fundamental, not a bug.
   - **Scoped variant (the ostree-motivated one):** use as lower a
     *bind of the target subtree* (`/usr`, or `/etc`) placed at an
     unrelated scratch path, and as upper the extracted store. The
     kernel's containment check compares the *real* paths (the lower's
     real path is under `/var/tmp/…`, the target's is `/usr`); sharing
     the underlying inode is fine. Verified on this kernel, in the
     exact apse sequence (single `unshare(CLONE_NEWUSER|CLONE_NEWNS)`
     syscall, single-extent `1000→1000` map, `rbind /` first):
     - `/usr`: btrfs upper, with and without the rbind context — both
       mount; the merged view is correct: added files appear and run,
       upper files **shadow** lower ones (a fake `/usr/bin/rpm`
       replaces the real one), lower files stay intact (the real
       `libc.so.6` keeps its ELF magic, `dnf5` still executable), and
       the usrmerge symlinks (`/bin`, `/lib`, `/lib64`, `/sbin`)
       resolve *through* the overlay (`/bin/<new-tool>` works).
     - `/etc`: same pattern; upper shadow (`motd`), upper addition
       (`profile.d/…`), lower pass-through (`os-release`) all correct,
       and a **single-file bind stacked on top of the /etc overlay**
       (the step-7.5 `hosts`/`hostname` pattern) still wins at its
       path — the per-instance identity files remain the last word.
     - Plain-directory variants (no rbind) and even a **tmpfs upper**
       all mount fine on this kernel.
   - One correction to an earlier session: that session reported *all*
     overlay-with-upper variants as failing (including tmpfs upper).
     Re-running the identical configurations in a harness faithful to
     apse's namespace creation, **all of them succeed** — the earlier
     failures were a harness artifact (finding #8), not a kernel
     limitation.

8. **Unprivileged `mount(2)` in a self-created user+mount ns works
   *before* `execve` and fails *after* it (single-extent non-root
   map); never use `unshare(1)` for probe harnesses.** Decisive A/B on
   this kernel: one process, one `unshare(CLONE_NEWUSER|CLONE_NEWNS)`,
   the map written directly by that process — `rbind / → /` **succeeds**
   before `execve`; the identical operation after `execve` into bash
   returns EPERM ("must be superuser to use mount"). Same SELinux
   context on both sides (`unconfined_t`, no transition, no AVC); the
   exact kernel rule is not documented here (this machine's kernel
   source tree is stripped of `capability.c`). Two consequences:
   (a) **apse is immune by construction** — A (the ns creator, never
   exec'd) performs all rootfs steps, and B (a fork) mounts `/proc`
   before its own exec; nothing in the pipeline mounts after `execve`.
   (b) **`unshare(1)`-based probes are untrustworthy for this work**:
   it always `exec`s the command (and has the map written by the
   setuid-root `newuidmap`/`newgidmap` helpers), so a single-extent
   non-root harness lands in the post-exec state and gets EPERM on
   *every* mount — including `mount --bind`. That is what produced the
   earlier session's false negative in #7. Write probes as
   python/ctypes: one `unshare(2)` call, direct `setgroups`/
   `uid_map`/`gid_map` writes, all mounts before any exec (a forked
   child that mounts before *its* exec works too — that is B).

9. **The overlay's write paths are exactly the ones the existing
   Landlock floor already denies (the shared store stays clean).** Raw
   namespace, no floor: (a) creating a *new* file under a root-owned
   lower dir **succeeds — the file lands in the upper** (store
   creation never touches the lower); (b) appending to a *root-owned*
   lower file is EPERM (in-ns 0 is unmapped, so root-owned inodes are
   the overflow uid, not ours) → **no copy-up**; (c) writing an
   *upper* file (owner 1000) **reaches the store on the host**
   (verified: the host-side copy gained the appended byte). In apse
   proper, `BASE_READ` grants `/usr` and `/etc` **read-only**, so all
   three are denied before they reach the overlay: no copy-up, no
   store mutation, **zero new app permissions** — the store is
   effectively immutable to the app (§3.3).

## 2. Where a toolchain can live (the visibility constraint)

The private-home design (decisions #43/#44) has a consequence that
shapes everything: the app's `$HOME` is a **private per-app state tree**
that *replaces* the real home, and `/var`, `/srv`, `/opt/*`, `/boot`,
`/media`, `/mnt` are masked. So:

- The only user-writable, persistent, *visible* space inside the
  sandbox is the per-app state tree (the app's `$HOME` and its XDG
  dirs) and the fresh `/tmp`.
- A toolchain store placed under the **real** home
  (`~/.local/share/…`) is **hidden behind the home bind**: its path
  resolves *after* the home is replaced, so a later `rw_bind` of it is
  a no-op self-bind onto the stand-in (decision #28's trap, one level
  up).
- `/var/tmp` (where the rootfs scratch lives) is masked in the app's
  view.

The mechanism that already solves exactly this is the **step-1
carry**: a **bind** of a host path into a scratch dir
(`mount(real_path → scratch/…, MS_BIND)` — a plain bind shares the
dentry tree, so it is **zero-copy**, the same pattern the per-instance
runtime dir and the per-app state tree use). The carry happens in step
1, *before* the home is replaced in step 7, so it reaches the real
store. For the overlay design, the carried dir *is* the upper (and the
per-instance workdir lives in scratch next to it); for the fallback
design, a step-7 bind from scratch exposes it as a prefix. Two binds,
no data movement, #28-safe ordering — the store needs no new plumbing
to participate in the rootfs, only to be *named* and *curated*.

## 3. Recommended shape: scoped `/usr` (+ `/etc`) overlay over a shared, curated store

### 3.1 Fetch & store (user side, no root)

A stable user-owned store, e.g.
`$XDG_DATA_HOME/apse/toolchains/<set>/`, with `usr/` and `etc/`
subtrees, produced by `dnf5 download --resolve --destdir` per package +
`rpm2cpio | cpio -idm` into the tree (the extraction keeps the
standard layout, so the store's `usr/` is exactly the set of files the
packages would install under `/usr`). Because of finding #3, the unit
of installation is a **curated set**, not a single tool name: e.g. a
`gcc` set = {`gcc`, `cpp`, `gcc-c++`, `binutils`, `glibc-devel`, …}.
The set definition (set → packages) is the maintenance surface — a
small table kept in sync with the release, extensible by the user.
Sets are **immutable once built** (a new set = a new directory, the
ostree deployment pattern); a profile references a set by name.

### 3.2 Build wiring (apse side) — one new rootfs step between 2 and 3

For a run whose profile selects set `N` (a new profile field, e.g.
`toolchain = "gcc"`):

- **step 1 (carry)**: bind `<store>/<N>` → `scratch/tc/<N>` —
  zero-copy, before the home is replaced in step 7 (#28-safe).
- **new step 2.5** (after the step-2 self-bind, before 7.5): for each
  target the set populates (`/usr` and `/etc`):
  `bind <ns>/usr → scratch/tc/lower/usr` (likewise `etc`);
  `mkdir scratch/tc/work/<N>-<instance>` (fresh per instance; it must
  be on the **same real filesystem** as the upper — on this target
  `/` and `/home` are one btrfs volume, so a workdir in scratch and an
  upper under the home-side store both sit on it; on a multi-volume
  host the workdir must live *inside the store tree* instead);
  `mount -t overlay -o lowerdir=scratch/tc/lower/usr,upperdir=scratch/tc/<N>/usr,workdir=… /usr`
  (likewise `/etc`).
- **step 7.5 is unchanged**: the per-instance `/etc/hosts`/`hostname`
  binds stack *on top of* the `/etc` overlay (later mount wins at that
  path — verified), so the identity files are still the last word.
- **steps 8–9 (masks, chroot) are unchanged**: `/usr` and `/etc` are
  not masked; the `/var` mask hides the scratch (the carried store and
  the workdirs included) from the app. The app sees the set's files
  **only** through the `/usr`/`/etc` overlay — exactly like natively
  installed packages.
- **teardown**: no explicit umounts — the whole mount namespace is
  destroyed with the process (the established pattern); the
  per-instance workdirs die with the scratch.

No environment surgery is needed: `gcc` lands at `/usr/bin/gcc`,
`cc1` at its standard path (the driver's `-print-search-dirs` relative
resolution, finding #5, works unchanged), the usrmerge symlinks
resolve through the overlay (verified), and the profile's existing
`[env]` remains available if a set ever wants one.

### 3.3 Why the shared store stays safe

Finding #9: every write path the overlay offers (new file → upper,
copy-up on a lower write, direct write to an upper file) is a *write*,
and the existing **read-only** Landlock grants on `/usr`/`/etc` deny
all of them in B (in confined mode, the label rules deny them too,
§6). Copy-up is therefore unreachable, the store is effectively
read-only to the app, and concurrent instances sharing a store are
sharing an *immutable source*. The per-instance workdir (step 2.5)
keeps the one remaining hazard — concurrent copy-ups *racing* inside
the kernel — out of a shared workdir; the kernel does not reject a
shared workdir (observed), so this is hygiene, not a hard requirement.

## 4. Alternatives considered

### 4.1 Full-`/` overlay — **rejected**

Mount an overlay with the extracted tree as an added lower over the
system root, so `gcc` appears "natively installed" at `/usr/bin/gcc`.
Finding #7 shows this is not practical on a single-root-filesystem
system: the root lower necessarily contains both the other lower and
the mount target, which overlayfs's loop detection rejects. Making it
work would require the host root to live on a *separate* filesystem
from the store and scratch (a loop device, or a dedicated volume) —
real, ongoing complexity for a convenience the scoped overlay (§3)
already provides. **This is the "unreasonable amount of effort" the
initial brief predicted** — and the evidence confirms the intuition
was right, for a subtler reason than "overlay is hard to mount" (the
mount itself is easy; the self-nesting on one root fs is the wall —
which scoping to `/usr`/`/etc` sidesteps entirely).

### 4.2 Separate prefix (the original recommendation) — fallback

The extracted tree exposed as a stable in-sandbox prefix via the same
carry (steps 1 + 7), wired with `[env]` `PATH`/`LD_LIBRARY_PATH`
prepending. Simpler than §3 (no overlay mount, no workdir, no `/etc`
interaction) and robust on kernels where the scoped overlay misbehaves;
costs are the environment surgery, non-default library paths for tools
that assume the standard ones, and weaker "natively installed"
semantics (a `gcc` at `<prefix>/usr/bin/gcc` instead of `/usr/bin/gcc`).
Keep as the fallback — the carry and env plumbing it uses is identical
to §3's, so switching is a profile-value change, not a rework.

### 4.3 Self-contained sysroot (cross-release) — optional escape hatch

`dnf5 download --alldeps` (the **full** closure, glibc included) into a
tree, and build with `--sysroot=<tree>` so the artifact links the
tree's own glibc instead of the host's. This eliminates mixing
*entirely* and is the correct tool when the user wants a toolchain
from a **different release than the host**. Costs: size (hundreds of
MB) and a build-flag convention the user must follow. Keep as a
documented advanced option, not the default — the default (§3) is
release-pinned and needs none of this.

## 5. The "library mixing" question, resolved

- **Same release as the host (the default):** no mixing is possible.
  The extracted tree has no glibc/libstdc++ of its own (finding #4);
  there is a single host glibc in the sandbox; artifacts link it. The
  overlay does not change this — the merged `/usr` still contains
  exactly one glibc (the host's), because the store contains none.
  Safe by construction, not by care.
- **Different release than the host:** mixing *is* a real risk (two
  glibcs, incompatible ABIs). The answer is §4.3 (sysroot) or, more
  simply, **pinning toolchains to the host's release** as the default
  policy and documenting the sysroot escape hatch for the rest.

## 6. Confined mode (SELinux)

- The store keeps its **uniform** label (finding #6): `user_home_t`
  under the home (the extraction dir's label; the store sits at
  `$XDG_DATA_HOME/apse/toolchains/…`). The app reaches those inodes
  **only** through the `/usr`/`/etc` overlay paths, and the app's
  existing home grants (decision #43: the full file lifecycle on the
  state tree, including execute) probably already cover read/execute
  of `user_home_t` — to be confirmed with a zero-denial run (the
  standard tuning loop). `cc1`/`collect2` are exec'd by the driver as
  **same-domain children** of the app (no new transition).
- The genuinely new surface is `apse_t` (process A) doing the overlay
  **`mount(2)`**: expect one `mountpoint`/fstype-related allow (the
  overlay fstype's context against the `usr_t`/`etc_t` targets), plus
  whatever label the overlay **superblock** ends up with (the upper's
  genfs context — `user_home_t` here — is the likely answer, which the
  app is already allowed to read). One or two new lines in
  `selinux/apse.cil`, same shape as the existing gap classes closed in
  v2.14.
- The per-instance `/etc` files (`apse_etc_t`, step 7.5) are bound on
  top of the overlay — the existing read-only rule carries over
  unchanged (verified the stacking in the unconfined probe).

## 7. Landlock

- **No new grants for the overlay design.** `BASE_READ` already grants
  `Read` on `/` and `/usr` (and `/etc`); the grants are on *paths*, so
  after step 2.5 they resolve to the overlay mount, whose root dentry
  (the upper's root inode) sits in the dentry chain of *every* path
  under `/usr` — lower-origin and upper-origin alike — and one Read
  grant therefore covers the whole merged view. Read-only is exactly
  what §3.3 needs. The step-7.5 `allow_file` grants on
  `/etc/hosts`/`hostname` are created in B *after* the overlay exists,
  so they bind to the scratch inode of the single-file bind that
  stacks over the overlay — the same as today.
- (The §4.2 fallback, if ever used, needs the `ro_binds`/ancestor-grant
  treatment instead: a `Read` grant on the prefix, plus any
  tool-writable subdirectory `ReadWrite` — as the earlier draft of
  this section described.)

## 8. Open questions

1. **Store location.** `$XDG_DATA_HOME/apse/toolchains/` (persistent,
   hidden behind the home bind, carried in step 1) vs. a non-home
   location. The workdir constraint (same real filesystem as the
   upper) is satisfied on this target by scratch (`/` and `/home` are
   one btrfs volume); on a multi-volume host the workdir must live
   inside the store tree instead.
2. **CLI surface.** A first-class `apse toolchain` subcommand
   (list/add/remove, driving `dnf5 download` + extraction; sets
   immutable) vs. a profile field plus a documented `dnf5` recipe the
   user runs by hand.
3. **Curation ownership.** Who maintains the set→packages table (the
   `gcc` set = {`gcc`, `cpp`, `gcc-c++`, `binutils`, `glibc-devel`, …})
   and how is it kept in sync across releases — a checked-in manifest
   the user can extend, versus per-user manifests? This is the real
   maintenance cost (finding #3).
4. **`/opt`.** Zero packages install there on this (ostree-laid-out)
   system, so the overlay targets only `/usr` + `/etc`. If a set ever
   ships `/opt` content, unmask via a profile `ro_bind` and add `/opt`
   as a third overlay target — the pattern is identical.
5. **Release-pinning policy.** Default toolchains to the host's release
   (no mixing, §5); document the sysroot escape hatch (§4.3) for
   cross-release needs.
