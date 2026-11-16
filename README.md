<p align="center">
  <img src="assets/apse-header-tagline.svg" alt="apse — unprivileged in-process sandbox for Wayland" width="587">
</p>

# apse

Run GUI applications (JetBrains IDEs, LibreWolf, …) in an **unprivileged
in-process sandbox** on a **Wayland desktop** (sway on Fedora is the
reference target; the actual requirement is that the compositor
advertises `wp_security_context_manager_v1` — see
[compositor requirements](#compositor-requirements--verify-your-setup))
while keeping the UX as close to unconfined as possible: windows are
**native Wayland clients** with **GPU rendering** — no VNC, no RDP, no
screen re-encoding, no blurry text. There are no containers: a single
Rust binary (`apse`) creates the sandbox itself — Linux
**user/mount/pid/ipc/uts/cgroup/net namespaces**, a rebuilt **private
rootfs**, and a **Landlock + seccomp** policy via the
[`nono`](https://crates.io/crates/nono) crate, applied by the binary
itself. The app runs as **your real uid** (never root, never another
user), looking and feeling like a normal local app. The threat model is
a supply-chain-compromised IDE extension (or a compromised browser
download): the sandbox must not reach host secrets, other users' files,
or privileged Wayland/D-Bus interfaces. This is a work in progress
(personal-laptop target: 1–2 human users).

## Why `wp_security_context_v1`

[wp_security_context_v1](https://wayland.app/protocols/security-context-v1)
is a Wayland *staging* protocol (from the wayland-protocols staging set;
wlroots implements it, and KWin does too, independently), intended for
an app to give a *child process* its own tagged Wayland socket. apse
repurposes it in the other direction: a **host-side** process tags a
listening socket so the *compositor* can identify the clients that
connect to it. How: `apse` connects to the host compositor, calls
`wp_security_context_manager_v1.create_listener()` on a listening socket
(setting the context's `sandbox_engine` — default `apse` — `app_id`,
`instance_id`), and holds the protocol's **reference pipe** (the
`close_fd`) open for the process's whole lifetime, so the tagged socket
stays valid; it is then the only Wayland socket the app is pointed at.
Because the tag travels *over the socket*, the compositor can apply
**per-context policy** to the client without any opt-out: hide
privileged globals from sandboxed clients, and it **must not** expose
`wp_security_context_manager_v1` to an already-tagged client — the
*nesting guard*, so a tagged client cannot stamp another socket (the
compositor side is checked in [verify your
setup](#compositor-requirements--verify-your-setup)). Three usage modes
use the tagged socket — **`run --wayland`** (default), **`wayland`**
(tag-and-park, the original mode kept as a fallback), **`wayland
--proxy`** (the transparent relay); details under [the Wayland
side](#the-wayland-side). In all three, the security context is how the
*compositor* discriminates; the sandbox (namespaces + rootfs + nono) is
how *filesystem, D-Bus and network* are discriminated. Containment is
layered:

| Layer | What it blocks |
|---|---|
| Unprivileged user namespace | the app is its **real uid** — never root, never another user. The single-extent self-map (`<uid> <uid> 1`) leaves in-ns `0` *unmapped*, so no `setuid`/`setgid` to a privileged id is possible and there is no privilege escalation path |
| Private rootfs (mount namespace) | other users' homes, `/root`, `/boot`, `/var`, `/srv`, `/media`, `/mnt` are **masked** (empty tmpfs); the app's `$HOME` and XDG dirs are a **private per-app state tree** (decision #43) and everything else read-only (a recursive self-bind of `/` is the base) |
| Landlock (nono) | a **default-deny** filesystem floor: even paths the rootfs *shows* (e.g. `/etc`) cannot be opened or written outside the grants; AF_UNIX sockets are restricted to the per-instance dir (plus a profile's explicit sockets) |
| seccomp-notify (nono) | `openat`, `connect`, `bind`, … are routed to the supervisor and **auto-denied** by default — the choke point for both file and network |
| cgroup + cgroup namespace | the app lives in its own per-instance sub-cgroup and sees only `0::/`; scoped under systemd (via D-Bus) for visibility/accounting, or a raw-cgroup fallback |
| pid namespace | the app is **PID 1** of a fresh pidns; it cannot see or signal host processes (signal mode `isolated` by default) |
| ipc namespace | POSIX shared memory only by default (no semaphores) |
| net namespace | the shared host netns by default (**egress is allowed** — see [threat model](#threat-model)) or a bare loopback-only netns with network blocked (`--network=none`) |
| Compositor policy (security context) | privileged Wayland globals/operations for sandboxed clients (see [verify your setup](#compositor-requirements--verify-your-setup)) |
| Wayland relay (`--proxy`, optional) | a **global allowlist** (hide non-allowlisted globals, reject their binds), the **selection receive-gate** (drop clipboard/primary-selection reads of data the app did not itself copy, optionally after a host-side consent prompt), a **copy-out** desktop notification, and the **selection audit log** (see [the relay](#the-transparent-relay-wayland---proxy)) |

## Architecture

### The sandbox: `S → A → B`

`apse run` builds the sandbox with a three-process pipeline (decisions
#12, #23–#26 in [PLAN.md](PLAN.md)):

```
S  apse (the supervisor — outside every namespace)
   │   • GPU precheck; creates the per-instance runtime dir
   │   • optional: registers a transient systemd user SCOPE via D-Bus
   │     (StartTransientUnit, PIDs=[self]) — or a raw-cgroup fallback
   │   • builds the tagged Wayland socket (if --wayland)
   │   • creates the handoff channels; forks A
   │   • receives B's seccomp-notify listener (pidfd_getfd + SCM_RIGHTS)
   │   • forwards SIGTERM/SIGINT/SIGHUP to the app; sd-notifies; waits
   │
   └─fork─► A  the intermediate child
            │   unshare user → mount → pid → cgroup
            │   builds the rootfs (as ns-"root" of its own mountns)
            │   forks B; reaps B; exits with B's status by choice
            │
            └─fork─► B  the app
                      unshare ipc → uts → net (per mode) → fresh /proc
                      nono: prepare landlock → install seccomp-notify →
                            apply the floor (all pre-exec)
                      execve (B is PID 1 of its pid namespace)
```

The supervisor stays *outside* the namespaces on purpose: it needs host
access (the compositor socket, the session bus, the cgroup files) and it
is the process the seccomp-notify fd belongs to. When `B` (PID 1) dies
the kernel's pidns teardown does *not* kill `A` on this kernel, so `A`
reaps `B` and exits with `B`'s status by choice — no orphans; the exit
code (or `128+signal`) propagates through both forks to `S`.

### What the sandboxed app sees

The **rootfs is rebuilt, not masked** (the old container-era "bind in
volumes" is gone). Working as the mount namespace's root, `A` assembles:

1. A recursive self-bind of `/` — the read-only base. (The `ro` flag is
   *not* set: it is silently dropped on a bind of a foreign superblock
   and `MS_REMOUNT` is `EPERM` unprivileged — decision
   #21; read-only behaviour comes from the app's real uid plus the nono policy instead.)
2. `/dev` — a **fresh tmpfs** with the standard nodes (`null`, `zero`,
   `full`, `urandom`, `random`, `tty`) **bind-mounted** (not `mknod`'d,
   so they keep their canonical genfs SELinux labels — what the SELinux
   module in `selinux/` needs for plain `open`/`read` rules), a **fresh
   `devpts` instance** isolated from the host's pts (`/dev/ptmx` is a
   symlink into it — binding the host's would hand the app the host's
   pty master), a **fresh private `/dev/shm`** (a `tmpfs`, mode 1777 —
   the `wl_shm` shared-memory path), and — with GPU on — `/dev/dri`
   bound from the host.
3. `/sys` — a fresh tmpfs with binds of `devices/` and `class/` (not
   read-only — decision #21, as with the self-bind; the sysfs *mount
   root* cannot be bound unprivileged — decision #18): all a GUI app
   needs for PCI/DRM discovery.
4. `/run` — a fresh tmpfs carrying **only** the per-instance dir
   (`/run/user/<uid>/apse/<app>-<instance>`), whose contents arrive from
   a build scratch on `/var/tmp` (decision #28): the tagged Wayland
   socket and the per-instance `etc/` dir (item 7). The host's own
   Wayland sockets sit directly under `$XDG_RUNTIME_DIR` and are
   deliberately *invisible* here — the app can reach only the tagged
   socket.
5. `/tmp` — a fresh tmpfs, sized by the profile (`tmp_size_mib`).
6. The app's **home and XDG dirs** (decisions #43/#44): a **private
   per-app state tree** under `$XDG_STATE_HOME/apse/<app-id>/` (home,
   config, cache, data, state subdirs — persistent across runs,
   disconnected from the real home and the host desktop) is bound over
   `$HOME` and the XDG locations; the profile's `rw_binds` layer on top.
7. **Per-instance `/etc` files** (task 8.10): `hosts` and `hostname` are
   generated into the per-instance runtime dir
   (`$XDG_RUNTIME_DIR/apse/<app>-<instance>/etc/`) and bound over the
   self-bind-layer `/etc`, so the sandbox's UTS name
   (`apse-<app>-<inst>`) resolves on loopback from `files` (`127.0.0.1`)
   — no DNS fallback or lookup timeouts. Static for the instance's
   lifetime: an in-sandbox `hostname <new>` changes the UTS name without
   touching these files (a known limitation); they are read-only for the
   app (Landlock grants `Read` only; in confined mode `apse_etc_t` is
   read-only).
8. **Masks** — empty tmpfs over `/root`, `/boot`, `/var`, `/srv`,
   `/media`, `/mnt`, every other user's `/home/*`, and `/opt/*` except
   the app's own dir, plus the profile's `mask`.

On top of the filesystem view, the **nono policy** (built identically in
`S` and re-run in `B` from one pure function, so the two cannot
disagree) is a default-deny `CapabilitySet`: **Read** on `/`, `/usr`,
`/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, `/proc`, `/sys`;
**read-write** on `/dev`, `/tmp`, the per-instance dir, and `$HOME`; the
profile's `ro_binds` (read), `rw_binds` (read-write), `unix_sockets`
(connect). The host netns stays shared by default (`--network=none` adds
`block_network()`); **signal mode** `isolated` (the app may only signal
itself and its descendants — Landlock V6) or `all`; **IPC mode** `shm`
(POSIX shared memory only) or `full`. Applied in three stages pre-exec
(decisions #22/#27): `prepare_landlock` (rule paths opened *before* any
filter exists) → install the combined seccomp-notify filter →
`apply_raw` (build the Landlock ruleset from the pre-opened fds,
re-assert `no_new_privs`, lock the single-extent identity); `B` blocks
on the verdict pipe before `execve`, so the handoff is deterministic —
the supervisor services the listener and **auto-denies** (decision #25).

### The Wayland side

- **Tagged socket** — created by `S` in the per-instance runtime dir
  (default socket name `wayland-1`); the app's `XDG_RUNTIME_DIR` is the
  *in-sandbox* instance dir and `WAYLAND_DISPLAY` the socket name.
- **Tag-and-park** (`wayland`, no `--proxy`) — bind, tag, sd-notify,
  park; the compositor accepts connections on the tagged listener
  directly. The third mode, **`wayland --proxy`** (the transparent
  relay, next section), forwards each connection to the compositor over
  a fresh tagged connection, re-parsing the protocol and applying
  optional policies on the way in.
- **Signal semantics are mode-dependent.** In `run`, `S` forwards
  `SIGTERM`/`SIGINT` to the app (then `SIGKILL` after 2 s — pidns-init
  ignores default-action signals) and `SIGHUP` terminates the app and
  exits **129** (decision #33 — no in-place rebuild of a live sandbox).
  In the `wayland` modes (tag-and-park, proxy) `SIGHUP` is a *rebuild*:
  an in-place re-exec of `/proc/self/exe` in `--listen` mode (same pid,
  fresh compositor connection and tag), or a clean exit for a systemd
  restart when socket-activated.

### The transparent relay (`wayland --proxy`)

The relay owns two sockets: a **public** socket the app connects to
(`--listen`) and a **tagged** socket held upstream (`--tagged-socket`),
which must be **unreachable from the app** (the [path
constraints](#running-the-relay-per-app) below). Every connection on the
public socket is relayed to the compositor over a fresh security-context
connection to the tagged socket, so the compositor applies per-context
policy while the app believes it is talking to an ordinary compositor.
It is a protocol *interpreter*, not a byte pipe: it re-parses the
messages it relays (interface tables generated from the protocol XML in
`protocols/`) and is **convention-adaptive** — Rust `wayland-backend`
uses display=ID 1 / client IDs from 2 / server IDs from `0xFF000000`,
while C `libwayland` uses display=ID 0 / client IDs from 1 / server IDs
from `0x80000000`; the first message of a connection pins the convention
for both ends. On the way *in* from the app it can apply:
- **`--allow-globals=<iface,…>`** — hide every other global from the
  registry and reject a bind of any name the app was never shown
  (`wl_display.error` `invalid_object`). Unset: pass-through, all
  globals shown; an explicitly *empty* value (`--allow-globals=`, no
  entries) is the opposite — an active allowlist that shows **no**
  globals, since an active-but-empty set allows nothing.
- **`--clipboard-policy=deny`** (default `allow`) — the **selection
  receive-gate**: a `receive` is forwarded only if the selection behind
  it was put on by the app itself (an own `set_selection`/`start_drag`
  is attributed to the next echoed offer, independently for the
  clipboard and the primary selection). A foreign read is dropped (the
  app's fd stays empty — it sees an empty clipboard) or, with
  `--broker-socket=…`, *asked about* by the broker and forwarded if the
  user approves (opening a 1500 ms intent window); every failure path
  (broker down, timeout) is a drop. A `receive` whose fd is not an
  in-memory channel (memfd/pipe/socket) is a **fatal protocol error** in
  both policies — compositors do not inspect the fd they are handed, so
  this check stops an app steering clipboard data into a file.
- **`--notify-copy-out`** (requires `--broker-socket`) — a one-way
  desktop notification to the broker each time the app *writes* to the
  clipboard or primary selection (`set_selection`) or *starts a drag*
  (`start_drag`): the copy-*out* signal, that data now being reachable
  by every client on the desktop. Rate-limited to at most one per second
  **per selection** (three independent one-second windows — clipboard,
  primary, drag; every write still lands in the audit log).
  Fire-and-forget/fail-open, independent of the policy above: a missing
  broker only loses the notice; the write is never blocked or altered.
- **The selection audit log** (always on, no flag) writes one structured
  `key=value` line per selection event the relay is on the path of:
  `set` (the app places data — the copy-out declaration), `read` (a
  `receive`, with the gate's decision — `forward` / `approved` through
  the broker / `dropped`), `clear` (a NULL `set_selection`), `serve` (a
  `send` on one of the app's source objects — the per-mime byte flow
  behind a write). The `selection` label is `clipboard` or `primary` by
  protocol, except a `serve` on the client's **active drag source** (a
  `start_drag` that has not yet ended) is labelled `drag` — the
  `wl_data_source` is shared by the clipboard and the drag and the wire
  does not say which (6.5.5). Fields: `app`, `instance`, `selection`,
  `action`, `origin`, `mime`, `gate`, `fd_kind`, `payload_bytes`, under
  the `audit` log target; **sizes, never content** (the relay only
  `fstat`s the fd it already holds; a pipe/socket reports no size, a
  dropped read records 0).

In deployment the relay's stderr reaches the **host** journal
(`StandardError=journal` / `LogDriver=passthrough` in whatever unit you
run it under), so `journalctl -u <unit>` shows one line per event;
`RUST_LOG=warn` silences the stream (the records are then simply not
retained).

### The prompt broker and the decider

The broker is a **host-side user service** (not in the sandbox — it must
reach the session bus for `notify-send`, and it is the thing that waits
for *you*). It speaks **N-D-JSON** with two request kinds, both over its
one socket (`$XDG_RUNTIME_DIR/apse-broker`):
- **`clipboard-read`** — request/response: the relay's gate dropped a
  foreign read and is asking for consent. The broker announces it with a
  desktop notification (carrying the prompt id and a ready-made reply
  command) and waits — default 30 s (`--broker-timeout-millis`); a
  timeout is a deny. Several prompts can be pending at once.
- **`clipboard-write`** — one-way: the relay fired it because the app
  wrote to a selection; the broker runs `notify-send` and closes with no
  reply. Fire-and-forget; a lost notification never affects the write.

The *user's* answer travels over a **second, session-scoped socket**
(`$XDG_RUNTIME_DIR/apse/decision.sock`, bound once at broker startup):

```sh
apse decide                       # list the pending prompts (oldest first, each with an id)
apse decide --decision allow      # resolve the oldest (or =deny)
apse decide --prompt 3 --decision allow   # resolve a named one
```

If the decision socket cannot be bound, the broker degrades: interactive
prompts are denied at once (`no-decision-socket`) instead of waited on;
`--auto-decide` mode never binds the socket at all (it answers every
request automatically — a test hook).

## The `apse` binary

Six subcommands (the relay logic lives in `src/proxy/`, the broker in
`src/broker.rs`, the sandbox in `src/sandbox/`):
1. **`run`** — run a command inside the sandbox (the `S → A → B`
   pipeline above). Options: `--app-id` / `--instance-id` (default `app`
   / `1`; feed the UTS hostname (`apse-<app>-<instance>`) and the
   per-instance cgroup name (`<app>-<instance>`); only
   `[A-Za-z0-9._-]`); `--network shared|none` (default `shared`);
   `--gpu` / `--no-gpu` (override the profile's GPU setting);
   `--wayland` (tagged socket for the app — see the Wayland side);
   `--listen <path>` (absolute as given, relative in the per-instance
   dir; implies `--wayland`) or `--socket-activation` (adopt the tagged
   socket from `LISTEN_FDS`); `--sandbox-engine` (default `apse`);
   everything after `--` is the command, e.g. `apse run -- /bin/sh -c
   'id'`.
2. **`wayland`** — set up a tagged Wayland socket (tag-and-park), or
   with `--proxy` run the transparent relay. Options: `--app-id` /
   `--instance-id` / `--sandbox-engine` (required, non-empty; `APSE_*`
   env vars honoured); `--listen <path>` (required unless
   `--socket-activation`) or `--socket-activation`; `--proxy` +
   `--tagged-socket <path>` (relay mode — the tagged socket must be
   unreachable from the app); `--allow-globals`, `--clipboard-policy
   allow|deny`, `--broker-socket
   <path>`, `--notify-copy-out` (the relay's policies, all proxy-only).
3. **`broker`** — the clipboard prompt broker (host user service):
   `--listen <path>` (required unless `--socket-activation`; the
   `APSE_SOCKET_PATH` environment variable is honoured) /
   `--socket-activation`, `--auto-decide <allow|deny>` (test hook),
   `--broker-timeout-millis` (default 30000,
   `APSE_BROKER_TIMEOUT_MILLIS` honoured).
4. **`decide`** — one-shot client of the broker's decision socket:
   `--decision allow|deny` (without it, lists the pending prompts) and
   `--prompt <id>` (omit: the oldest). Intended for a keybinding or a
   notification action.
5. **`dbus-proxy`** — a host sidecar wrapping `xdg-dbus-proxy` that
   bridges the session bus to a per-instance public D-Bus socket (the
   app's `DBUS_SESSION_BUS_ADDRESS` points at it): `--app-id` /
   `--instance-id` (default `app` / `1`), `--bus-address` (default the
   `DBUS_SESSION_BUS_ADDRESS` environment variable), `--socket-name`
   (default `bus.sock`), repeatable `--see` / `--talk` / `--own`
   (bus-name rules) and `--call` / `--broadcast` (`NAME=RULE` rules),
   `--proxy-bin` (default `xdg-dbus-proxy` on `PATH`).
6. **`xwayland`** — the optional host-side satellite giving the
   sandboxed app a per-instance X display (a host-side Xwayland client
   of the desktop compositor; the X socket and the MIT auth file live in
   the instance runtime dir's `x/` subdir — decision #47 — and the app's
   `DISPLAY` / `XAUTHORITY` point at them): `--app-id` / `--instance-id`
   (default `app` / `1`), `--display` (default `97`), `--socket-name`
   (default `xwayland.sock`), `--auth-name` (default `xwayland-auth`),
   `--wayland-display` (default the `WAYLAND_DISPLAY` environment
   variable), `--xwayland-bin` (default `Xwayland`), `--no-rootless`
   (rootless is the default).

## Install

One binary and (optionally) one user unit:
1. **Build.** `cargo build --release` → `target/release/apse`. Install
   it wherever you like; the broker unit below expects
   `/usr/local/bin/apse` (override `ExecStart` in a drop-in if yours
   lives elsewhere).
2. **Install the broker unit.** Copy
   `systemd/user/apse-broker.{socket,service}` to
   `~/.config/systemd/user/`.
3. `systemctl --user daemon-reload`
4. **(Optional) enable the broker.** `systemctl --user enable --now
   apse-broker.socket` — socket-activated, dormant until a proxy asks it
   about a dropped read. Only the relay (consent prompt, copy-out
   notification) needs it; tag-and-park and plain `run` do not touch it.
5. **Add your app profile(s)** (next section) and run.

You need to be in the **`render` group** for GPU access (the `/dev/dri`
nodes are bind-mounted into the sandbox); without it, pass `--no-gpu`.

## Adding an app

An app is described by a **TOML profile** at
`~/.config/apse/apps/<app-id>.toml` (the replacement for the old quadlet
drop-ins). The file is optional: built-in defaults cover the known apps
(`rustrover` → `/opt/rustrover`, `librewolf` → `/usr/lib64/librewolf`);
a profile-less `run` (an ad-hoc command) falls back to an ad-hoc default
(no GPU). A malformed file is a **hard error**. All path fields are
absolute (`~` is not expanded — profiles are data, not shell).

```toml
# ~/.config/apse/apps/rustrover.toml

gpu = true                 # build /dev/dri in the sandbox (CLI --no-gpu overrides)
tmp_size_mib = 2048        # size of the fresh /tmp (0 = kernel default)

# Everything under / is already read-only from the self-bind; ro_binds
# document the app's install dir and exempt it from the /opt/* mask.
ro_binds = ["/opt/rustrover"]

# Extra writable self-binds, on top of the app's private
# per-app home/XDG tree (decision #43).
rw_binds = []

# Extra paths to mask (an empty tmpfs over them), on top of the
# defaults (/root, /home/* except ours, /boot, /var, /srv, /media,
# /mnt, /opt/* except the app's).
mask = []

# Environment variables added for the app, on top of the session env.
[env]
# JAVA_TOOL_OPTIONS = "-Dawt.toolkit.name=WLToolkit"

# AF_UNIX socket paths the app may use, on top of the per-instance dir
# (the tagged wayland socket).
unix_sockets = []

ipc = "shm"                # "shm" (POSIX shm only; default) or "full" (also semaphores)
signals = "isolated"       # "isolated" (default; app signals only itself/descendants) or "all"
```

Then run it:

```sh
# a plain command (ad-hoc, no app profile, no Wayland):
apse run -- /bin/sh -c 'id && ls /root'

# a GUI app with a tagged Wayland socket:
apse run --app-id rustrover --instance-id 1 --wayland -- /opt/rustrover/bin/rover

# cut the network:
apse run --app-id rustrover --wayland --network none -- /opt/rustrover/bin/rover
```

## Running the relay (per-app)

Per-app proxies are **documented manual runs, not a systemd template
unit** (decision, [PLAN.md](PLAN.md) §7.1): the public socket's path
must match the socket the app's environment points at (`XDG_RUNTIME_DIR`
+ `WAYLAND_DISPLAY`) — per-instance coordination a template instance
cannot derive. Two constraints on the paths:
- the **public** socket must land *inside* the per-instance runtime dir
  (that dir is what the app sees as its `$XDG_RUNTIME_DIR`), so the app
  can reach it;
- the **tagged** socket must sit *outside* the per-instance dir (e.g. as
  a sibling under `$XDG_RUNTIME_DIR/apse/`), so the app cannot reach it
  — a socket the app can reach that is also a valid tagged socket would
  let it bypass the relay.

```sh
# from a terminal, or a one-off `systemd-run --user --scope`:
apse wayland \
  --app-id rustrover --instance-id 1 --sandbox-engine apse \
  --listen "$XDG_RUNTIME_DIR/apse/rustrover-1/wayland-1" \
  --tagged-socket "$XDG_RUNTIME_DIR/apse/rustrover-1.tagged" \
  --clipboard-policy deny \
  --broker-socket "$XDG_RUNTIME_DIR/apse-broker" \
  --notify-copy-out
```

Then point the app at the public socket from its profile and start it
**without** `--wayland` (the relay owns the tagged socket — `run` must
not create a second one). The profile's `[env]` section sets both
variables to the *in-sandbox* instance dir, whose location is fixed at
`/run/user/<uid>/apse/<app>-<instance>` regardless of the host's
`XDG_RUNTIME_DIR`:

```toml
# ~/.config/apse/apps/rustrover.toml — routing the app through the relay
[env]
XDG_RUNTIME_DIR = "/run/user/1000/apse/rustrover-1"
WAYLAND_DISPLAY = "wayland-1"
```

```sh
apse run --app-id rustrover --instance-id 1 -- /opt/rustrover/bin/rover
```

The chain works end-to-end: a sandboxed Wayland client is driven through
the relay into the live compositor (verified with `wayland-info`
enumerating sway's globals and exiting 0) — the public socket sits in
the per-instance runtime dir, which the rootfs build carries into the
sandbox (item 4 above), so the app's `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`
resolves to it without any `run --wayland` tag of its own.

**Audit sink.** Run the relay under a unit (or `systemd-run --user`)
that sends its stderr to the host journal, so the selection audit log is
persistent and greppable:

```ini
[Service]
ExecStart=/usr/local/bin/apse wayland --proxy …
StandardError=journal
LogDriver=passthrough
```

`journalctl -u <unit>` then shows one `audit:` line per selection event.

## Compositor requirements & verify your setup

- The compositor must provide the staging global
  `wp_security_context_manager_v1`. Every **wlroots**-based compositor
  that exposes it qualifies (sway, wayfire, river), and KWin has an
  independent implementation — but GNOME/mutter has none (its privileged
  operations are only on D-Bus-originated connections), so it is not a
  target. If it is absent, `apse` exits with an actionable error
  pointing at the check below.
- The compositor must be willing to enforce per-context policy on
  security-context clients (that is what makes this more than
  labelling), and must not re-expose the manager to a tagged client (the
  nesting guard).

**Verify:** install a Wayland inspector (e.g. `wlsinfo` from
`wayland-utils`, or `wayland-info`) and diff what a sandboxed client
sees against the host:

```sh
# on the host:
wlsinfo          # globals the unconfined client sees
wlsinfo -t       # staging globals — wp_security_context_manager_v1
                 # must be present here

# the sandboxed view (a `run` of the inspector against the tagged socket):
apse run --app-id probe --instance-id 1 --wayland -- /usr/bin/wlsinfo
```

Diff the two global lists. Privileged globals **should be absent** from
the sandboxed view — notably screencopy (`zwlr_screencopy_manager_v1`),
data control / screen capture (`zxdg_data_control_v1`), virtual keyboard
/ pointer (`zwp_virtual_keyboard_v1`, `zwp_virtual_pointer_v1`),
foreign-toplevel management (`zwp_foreign_toplevel_manager_v1`), and
input method (`zwp_input_method_manager_v1`).

Exactly which globals your compositor hides for a security-context
client is *its* policy, not apse's — treat the diff as your own
acceptance checklist, and file upstream if the set is wider than you
expected. On sway on this desktop the host shows 56 globals, the tagged
socket 35, and `wp_security_context_manager_v1` is present on the host
(name 34) but absent on the tagged socket.

## Threat model

**What apse protects:** everything the layered table above provides —
plus, beyond the table: the host session bus (unreachable by default —
its socket is not in the rootfs and AF_UNIX is Landlock-restricted to
the per-instance dir); the host desktop's clipboard and primary
selection from sandboxed reads (the relay's **selection receive-gate**);
and — optionally, where the local `apse` SELinux module is installed
(phase 8.2) — a **type-confinement layer**: the stack runs `apse_t`
(supervisor/pipeline/sidecars), the sandboxed app `apse_app_t` (a
compromised app is confined to its allow-set), each instance in its own
MCS category `cN` (base MLS constrain: a `cN` subject may only
signal/ptrace/transition a same-`cN` process — *stronger* than podman's
two-category `cNNN,cMMM` model). In every mode, filesystem containment
comes from the namespaces + landlock rootfs — the MCS layer is
process-level, not file-level (see below).

**What it does NOT protect (residual risk, by design or by necessity):**

- **Outbound network access.** By default the app shares the host netns
  and egress is *allowed* (the IDE needs it); nothing here blocks it,
  nor guarantees the host's own services (local SOCKS/proxy listeners,
  the host's address) are unreachable. `--network=none` gives a bare
  loopback-only netns with network blocked; a finer-grained egress
  filter (Landlock v4 network rules / the seccomp `connect` trap) is a
  later phase.
- **Copy-out via the clipboard.** The receive-gate only protects *reads
  of* host data: the app can still put its own data on the clipboard or
  primary selection (`set_selection`/`start_drag` are relayed), and the
  host desktop can then read it — an exfiltration channel anyone on the
  host can see. Blocking it would break the app's own copy-and-paste, so
  the write is **not blocked**; it is made *visible* instead — the
  `--notify-copy-out` tripwire (opt-in, fail-open, rate-limited; [the
  relay](#the-transparent-relay-wayland---proxy)) and the always-on
  selection audit log in the host journal. The clipboard is shared
  scratch space, not a secret boundary.
- **GPU render-node access.** With GPU on, the app gets raw
  `/dev/dri/renderD*` nodes (bind-mounted) for native rendering; a bug
  in the GPU stack (driver/firmware) is an escape path this project does
  not mitigate — the price of "no VNC, no re-encoding".
- **Your own home directory.** The app is your real uid, so the files it
  creates are yours on the host; (decision #43) its `$HOME` and XDG dirs
  are a **private per-app state tree**
  (`$XDG_STATE_HOME/apse/<app-id>/`), so a compromised app can tamper
  only with its own persistent state.
- **Portal attribution.** When the `apse dbus-proxy` sidecar (Phase 7.2)
  sits in front of the session bus, portal calls are proxied to the
  *host's* portal, which attributes them to the **host** desktop, not
  the sandbox — the `sandbox_engine`/`app_id`/`instance_id` context
  travels only over Wayland, not over D-Bus (without the sidecar there
  is no D-Bus path at all; the session bus is simply unreachable).
- **Within one app.** All processes of *one* app instance share its
  namespaces — isolated from *other* instances, not from each other; the
  supervisor nonetheless services the app's *children* as well (decision
  #32), so a multi-process app does not deadlock.
- **SELinux MCS is process-level, not file-level.** The per-instance
  category `cN` isolates the instances' **processes** (a `cN` subject
  can only reach a same-`cN` process), but not the **objects** they
  create: under the live policy's `default_range … target low` rule, a
  `dir`/`file`/`sock_file` created under the `s0` runtime parent takes
  the *parent's* low level — `s0` — and any `cN` dominates plain `s0`,
  so every instance (and the `s0` broker) can read and write them;
  file/dir separation between instances comes from the namespaces +
  landlock rootfs (LESSONS #29). Relatedly, this kernel's process class
  splits `signal` into `signull` (kill 0), `sigkill` and `signal`, and
  the base MLS constrain does **not** cover `signull`; a module CIL
  cannot add one, so the supervisor's kill -0 liveness probe is not
  category-scoped — practical impact minimal (kill -0 only reveals a
  process's existence, which `/proc` already does; LESSONS
  #33).

**SSH / git:** do not mount private keys into the sandbox. Use
`ssh-agent` forwarding instead: keep the agent on the host, run `ssh-add
--constrain usage=sign,confirm=yes <key>` (so even a compromised agent
client cannot ask the key for decryption or use it without
confirmation), and let the app reach the agent's socket: list the host's
`$SSH_AUTH_SOCK` in the profile's `unix_sockets` (the Landlock connect
grant), with the socket's path also bound into the rootfs (the fresh
`/run` carries only the per-instance dir).

## Known gaps / WIP

- **Multi-process apps work (decision #32).** The supervisor services
  *every* trapped notification on the listener — no pid filter — so a
  child that inherits the seccomp filter is served with the same
  capability set, and a failed verdict answers `EPERM` rather than
  hanging; the Phase 5.5 Firefox e2e (browser + gecko/socket children)
  ran and exited cleanly.
- **FOOT/PTY works (decision #39).** The fresh `devpts` instance is
  mounted `MS_NOSUID` only — never `MS_NODEV` — so a terminal that
  allocates a fresh PTY inside the userns works (the earlier `EACCES`
  was apse's own `MS_NODEV` on that mount — the VFS `may_open_dev` gate,
  decided before any LSM hook — not a kernel/userns restriction; `foot`
  runs clean through the relay, v2.14).
- **A `read` during a drag is labelled by its protocol, not its drag.**
  The `set` of a `start_drag` and the `serve` records on the active drag
  source are labelled `selection=drag` (the relay tracks the active drag
  — Phase 6.5.5), but the `read` on the stable-protocol data offer that
  a drag creates is labelled `selection=clipboard` — the protocol never
  says which selection a `receive` belongs to, so the stable-protocol
  offer can only carry the stable-selection label.
- **The sidecars are opt-in, not on by default.** `apse dbus-proxy`
  (Phase 7.2) and the optional `apse xwayland` satellite (Phase 7.3) run
  per instance; a plain `run` starts neither, so out of the box the host
  session bus is simply unreachable and there is no in-sandbox X server.
- **SELinux: local module built, installed and tuned (enforcing-mode
  tuning loop done, 2026-10-29).** `selinux/` ships a local module
  (`apse`) defining `apse_t` (supervisor/pipeline/sidecars) and
  `apse_app_t` (the sandboxed app), plus the `xserver_t` rules found
  missing in reconnaissance and the per-instance MCS mechanics
  (`src/mcs.rs`). The policy is written **directly in CIL** —
  `selinux/apse.cil` is the single source of truth *and* the install
  artifact (`sudo semodule -i selinux/apse.cil`, then `sudo restorecon
  -v /usr/local/bin/apse` for confined mode; no `.te`/`checkmodule`, no
  `build.sh`); installed, the stack is confined, and the tuning loop
  (audit2allow against a confined run, iterated until a confined
  `echo`+`cat`+`ls` produced zero denials) closed the known allow gaps.
  It deliberately does *not* do **file-level** separation (created
  objects are `s0`, not `cN`) nor the `signull` (kill -0) category gap —
  both unfixable in a module CIL (see the residual-risk bullets).
  Uninstalled, the stack runs unconfined exactly as before: the module
  is a second containment layer on top of the namespaces + nono, not a
  replacement.
