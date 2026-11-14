# Adding build toolchains to the sandbox (no host root) — design sketch

Status: **exploration / feasibility** (written 2026-11-14). Every finding
below was hands-on-verified this session on the Fedora 45 target —
unprivileged user (uid 1000, `unconfined_t`), kernel
`7.3.3-300.fc45.x86_64`, `/` + `/home` + `/var` on one btrfs volume
(`/dev/vda3`), `/tmp` on tmpfs, `dnf5` 5.4.7, `rpm2cpio`/`cpio`
present, glibc 2.44. No code or profile changes yet; this is the
working sketch to decide the feature's shape. The recommendation is in
§3; the rejected overlay route and *why* it is the "unreasonable
effort" is in §4.1.

The question this documents: how does a sandboxed app get **build
tools** — compilers, `make`, and the like — that are **not installed on
the host**, i.e. without `dnf install` / root, while staying inside the
isolation we already have (namespaces + the rebuilt rootfs +
landlock/seccomp via nono, the private per-app home, and, in confined
mode, the SELinux module)? Two candidate shapes were on the table:
overlaying RPM packages onto the system root, or carrying a toolchain
as a separate directory. The evidence decides between them.

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
   (`user_tmp_t:s0` under `/tmp`, `user_home_t` under the home) — the
   RPMs' original per-file labels are not restored (LESSONS #57: on
   7.2 `filecon` does not label created inodes). In confined mode this
   is *simpler*, not worse: one label covers the whole tree, so the
   module needs execute/read grants on a single type (§6).

7. **Unprivileged overlayfs works on this machine — but a full-`/`
   overlay is not practical here.** Verified inside a throwaway
   user+mount ns:
   - a **read-only two-lower** overlay (no upper) mounts fine and is
     correctly read-only (writes → `Read-only file system`);
   - a **btrfs upper** (copy-up) works; a tmpfs upper is the common
     case;
   - **overlaying onto `/` with `/` itself as a lower is rejected** —
     the lower contains the mount target (self-referential);
   - the natural workaround (**`--rbind /` to a scratch dir first, then
     overlay with lower = `<tree> : <rbind-of-/>`**) is *also* rejected
     by overlayfs's loop detection (`ovl_validate`): the extracted
     tree *and* the mount target are both path-nested under the root
     lower. On a single-root-filesystem system (here `/`, `/home`,
     `/var` are all one btrfs) this is fundamental, not a bug to
     work around.

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
store. A step-7 bind from that scratch dir onto a stable in-sandbox
path then exposes it to the app. Two binds, no data movement,
#28-safe ordering — the toolchain store needs no new plumbing to become
visible, only to be *named* and *curated*.

## 3. Recommended shape: extracted tree + curated set + carry + env

### 3.1 Fetch & store (user side, no root)

A stable user-owned store, e.g.
`$XDG_DATA_HOME/apse/toolchains/<name>/`, produced by
`dnf5 download --resolve --destdir` per package + `rpm2cpio|cpio -idm`
into the tree. Because of finding #3, the unit of installation is a
**curated set**, not a single tool name: e.g. a `gcc` set =
{`gcc`, `cpp`, `gcc-c++`, `binutils`, `glibc-devel`, …}. The set
definition (set → packages) is the maintenance surface — a small table
kept in sync with the release, extensible by the user.

### 3.2 Carry & bind (apse side)

A new profile field (or `--toolchain`), e.g. `toolchains = ["gcc"]`.
On `run`, apse extends the existing carries:
- **step 1**: bind the store `<store>/<name>` → `scratch/tc/<name>`
  (zero-copy, before the home is replaced — #28-safe);
- **step 7**: bind `scratch/tc/<name>` → a stable in-sandbox prefix
  (see the open question in §8.2 for the exact path).

### 3.3 Environment wiring

The profile's `[env]` already merges over the session environment
(`app_env` → `cmd.envs()`), and a full `PATH` override is permitted.
So wiring a toolchain is just: prepend `<prefix>/usr/bin` to `PATH`
(and `LD_LIBRARY_PATH` only if a set carries its own private libs). No
change to the exec path is needed — the existing env mechanism carries
it.

## 4. Alternatives considered

### 4.1 Full-`/` overlay — **rejected**

Mount an overlay with the extracted tree as an added lower over the
system root, so `gcc` appears "natively installed" at `/usr/bin/gcc`.
Finding #7 shows this is not practical on a single-root-filesystem
system: the root lower necessarily contains both the other lower and
the mount target, which overlayfs's loop detection rejects. Making it
work would require the host root to live on a *separate* filesystem
from the store and scratch (a loop device, or a dedicated volume) —
real, ongoing complexity for a convenience the separate-prefix shape
already provides. **This is the "unreasonable amount of effort" the
initial brief predicted** — and the evidence confirms the intuition was
right, for a subtler reason than "overlay is hard to mount" (the mount
itself is easy; the self-nesting on one root fs is the wall).

### 4.2 Per-app copy inside the state tree — viable minimal fallback

Put each toolchain under the app's private `$HOME` (the per-app state
tree). Zero new plumbing — it is already visible and writable through
the existing home/XDG binds. Costs: the store is **duplicated per app**
(every app that wants `gcc` carries its own 40–200 MB), and a
toolchain living in the app's *state* is semantically wrong (state is
the app's data, not shared system tooling). Fine as a stopgap, not the
target design.

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
  separate-prefix shape is therefore safe by construction, not by
  care.
- **Different release than the host:** mixing *is* a real risk (two
  glibcs, incompatible ABIs). The answer is §4.3 (sysroot) or, more
  simply, **pinning toolchains to the host's release** as the default
  policy and documenting the sysroot escape hatch for the rest.

## 6. Confined mode (SELinux)

- The extracted tree carries a **uniform** label (finding #6):
  `user_home_t` if the store sits under the home, or a dedicated
  `apse_toolchain_t` if we choose to relabel it at carry time.
- `apse_app_t` needs `read` + `execute`/`execute_no_trans` on that one
  type (and on the containing dir). If the tree stays under the home
  with the home label, the existing home grants (decision #43: the app
  has the full file lifecycle on the state tree, incl. execute)
  probably already cover it — to be confirmed with a zero-denial
  run. `cc1`/`collect2` are exec'd by the driver as **same-domain
  children** of the app (no new transition), so only execute grants are
  at issue.
- If we relabel to a dedicated `apse_toolchain_t`, that is a one-time
  addition to `selinux/apse.cil` (a filecontext + the app's read/exec
  grants), the same shape as the existing `apse_etc_t`.

## 7. Landlock

- The in-sandbox prefix needs a `Read` grant in `policy.rs` (the same
  treatment as `ro_binds`), plus the **ancestor** grants decision #24
  calls for (`/` is already Read-granted; a new top-level prefix would
  need its chain). Any toolchain-writable subdirectory (a tool's own
  cache) needs `ReadWrite`.
- If the prefix lives **inside the home tree** (which already has a
  `ReadWrite` grant for the app), **no new landlock rule is needed** —
  a point in favour of the `$HOME/.toolchains/<name>` prefix (§8.2).

## 8. Open questions

1. **Shared store vs per-app.** Carry one shared store (bind per app,
   zero-copy) or keep it per-app in the state tree (§4.2)? The carry
   being a zero-copy bind (§2) removes the main cost of "shared", so
   the lean is toward **shared store + carry**.
2. **In-sandbox prefix.** `$HOME/.toolchains/<name>` (no new landlock
   or SELinux surface, but it sits in the app's home) vs a new
   top-level path such as `/opt/apse/<name>` or `/usr/apse/<name>`
   (cleaner semantics, but new landlock/ancestor grants and a
   `ro_binds` mask-exemption, since `/opt/*` is masked by default).
3. **CLI surface.** A first-class `apse toolchain` subcommand
   (list/add/remove, driving `dnf5 download` + extraction) vs. a
   profile field plus a documented `dnf5` recipe the user runs by
   hand.
4. **Release-pinning policy.** Default toolchains to the host's release
   (no mixing, §5) and document the sysroot escape hatch (§4.3) for
   cross-release needs.
5. **Curation ownership.** Who maintains the set→packages table and how
   is it kept in sync across releases (a checked-in manifest the user
   can extend, versus per-user manifests)?
