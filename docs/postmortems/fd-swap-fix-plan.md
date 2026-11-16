# Handoff plan — fd misrouting in `Relay::forward()` (critical,
# LANDED — kept as a post-mortem)

**Status: fixed.** Landed in commit `88d237e`
(`apse: fix fd misrouting when a datagram carries several
fd-bearing messages`): the `drain(0..take)` front-slice fix in
`forward()` plus the regression test
`two_fd_messages_in_one_datagram_keep_their_fds` (verified to fail
with swapped sentinels pre-fix, to pass with it). The
`TASKS.md` "Critical (open defect)" section and the `AGENTS.md`
pointer are removed; this file is kept as the post-mortem record.

Found in the Phase 1–9 clipboard-feature code review (2026-10-15,
HEAD `fa4eee8`).

## 1. What is wrong, in one paragraph

For each complete message in a received datagram, `forward()`
should give it the *first* `n_fds` of `recv()`'s arrival-order
queue, but the `split_off`/`pop_front` sequence (§2) hands over the
*last* ones. So with two or more fd-carrying messages in one
datagram, the i-th message is paired with the (n−1−i)-th fd (two
fds: an exact swap) and re-sent with the wrong fd; with exactly
one fd, `take == len` and it happens to be correct — which is why
every existing test (all single-fd) passes.

## 2. Root-cause code

`src/proxy/mod.rs`, `Relay::forward()`, lines ~628–642:

```rust
// The parse validates the message against the signature and
// consumes the fds that belong to it (in order).
let n_fds = desc
    .signature
    .iter()
    .filter(|t| matches!(t, ArgumentType::Fd))
    .count();
let take = src_fds.len().min(n_fds);
let mut scratch = src_fds.split_off(src_fds.len() - take);   // ← takes the TAIL
let (msg, rest) = wire::parse_message(raw, desc.signature, &mut scratch)
    .map_err(|e| RelayEnd::Protocol(e.to_string()))?;
```

`src/proxy/wire.rs` (~line 111) consumes from the front:

```rust
if let Some(front) = fds.pop_front() {
    Ok(Argument::Fd(front))
} else {
    Err(Error::MissingFd)
}
```

Supporting plumbing — all **correct, do not change**:

- `recv()` (~230): appends every `SCM_RIGHTS` fd from one `recvmsg`
  to the deque, in arrival order.
- `pump()` (~549): passes the same `&mut fds` to each `forward()`.
- End of `forward()` (~1000–1015): rebuilds `out_fds` from the
  *parsed* args and calls `dst.send(raw, &out_fds)` — the fd chosen
  at parse time is exactly the one forwarded.

## 3. When it triggers

- wayland-backend 0.3.11's `BufferedSocket::flush()` (registry
  `socket.rs` — doc comment at line 38: "A single socket message
  can contain several wayland messages"; implementation at line
  152, §9) sends **all** buffered messages plus **all** buffered
  fds in a single `sendmsg`; the C libwayland client does the same
  in `wl_display_flush`.
- An app that issues two or more `wl_data_offer.receive` /
  `zwp_primary_selection_offer_v1.receive` calls in one dispatch
  cycle — the ordinary multi-mime paste (`text/plain` +
  `text/html`) — or a compositor that flushes two or more `send`
  events at once, produces one datagram carrying multiple fds.
- Effect: for a `receive` batch, the (host-side) selection owner
  writes mime *i*'s payload into the app's buffer registered for a
  different mime; for a `send` batch, the app's data lands in the
  wrong requester buffer — user-visible: cross-wired/garbled
  multi-mime pastes.
- The defect predates the clipboard phases (3+) — it dates to
  Phase 1, when `forward()` was written — but multi-`receive`
  batches are exactly what the gate now sees on every paste.

## 4. Why this is not a security regression

- The gate's forward/drop decision (`ClipboardGate::on_receive`) keys
  on `msg.sender_id` (the data-offer object) plus the origin
  attribution; the fd is only *class-checked* (must be an in-memory
  channel) and never part of the decision.
- A dropped `receive` is consumed with its (mispaired) fd and nothing
  is forwarded to the compositor, so it is never served.
- No data the gate would have denied crosses the boundary; only
  the *pairing* of already-permitted data with the app's own
  buffers is scrambled.

## 5. The fix

In `forward()` (`src/proxy/mod.rs` ~635–636), replace

```rust
let take = src_fds.len().min(n_fds);
let mut scratch = src_fds.split_off(src_fds.len() - take);
```

with

```rust
let take = src_fds.len().min(n_fds);
let mut scratch: VecDeque<OwnedFd> = src_fds.drain(0..take).collect();
```

Rationale: take the *first* `take` fds (the ones belonging to this
message) in arrival order; the remainder stays in `src_fds` for
the next message in the batch. `take ≤ src_fds.len()` by
construction, so the range is always valid; `take == 0` yields an
empty `scratch` as before. The `wire.rs` `pop_front` contract is
untouched.

Equivalent explicit form, if the iterator feels subtle:

```rust
let mut scratch = VecDeque::with_capacity(take);
for _ in 0..take {
    if let Some(f) = src_fds.pop_front() {
        scratch.push_back(f);
    } else {
        break;
    }
}
```

## 6. Regression test — the crux of the change

`relay_passes_messages_and_fds` (`tests/proxy_integration.rs:635`)
sends exactly **one** fd (via `one_app_session`, line 553 — a
single pipe) and only asserts the compositor *received* an fd. The
new test asserts **per-fd content**:

New test: `two_fd_messages_in_one_datagram_keep_their_fds` in
`tests/proxy_integration.rs`, reusing the existing clipboard
harness (`run_fake_data_device_compositor`, line 1030, and the
`Srv2` / `OfferState` machinery — the foreign branch of
`Srv2::request` already writes `data.data` into each received
`receive` fd).

Client→server variant (the minimum viable version):

1. The fake compositor advertises **two** foreign `wl_data_offer`
   objects, each with a distinct mime and a distinct sentinel
   payload in `OfferState.data` (e.g. `text/plain` /
   `b"PLAIN-SENTINEL"` and `text/html` / `b"HTML-SENTINEL"`).
2. The app (a real `wayland-client`, like the existing `App`
   handler) issues `offer_a.receive("text/plain", fd_a)` and
   `offer_b.receive("text/html", fd_b)` **back to back, without a
   roundtrip between them**, so the client's event queue coalesces
   both requests into one `sendmsg`.
3. The fake serves each `receive` from its own sentinel (existing
   foreign-branch behavior).
4. The app reads both of its fds and asserts: `fd_a` contains
   `PLAIN-SENTINEL` **and** `fd_b` contains `HTML-SENTINEL`. Under
   the current code the two are swapped → the test fails; after
   the fix it passes.

Server→client variant (optional; the fix is direction-agnostic, so
this is a belt-and-braces extra): batch two `send` events into
one `flush()` from the fake; the app's `wl_data_source` handler
writes a distinct payload into each received fd; the fake reads
the fds back and asserts the mime→payload pairing.

If getting the real wayland-client to deterministically batch two
fd-carrying requests proves flaky, the fallback is a lower-level
test: expose `pump` (or a small forward-level helper) as
`#[cfg(test)] pub(crate)` and feed it a hand-built two-message
byte buffer plus two `OwnedFd`s (pipe or memfd, each pre-seeded
with a sentinel). The integration version is strongly preferred —
it exercises the real `recvmsg`/`sendmsg` path.

## 7. Verification

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
```

All 14 existing integration tests plus the new one, and all unit
tests, must pass. Note: `clipboard_session_is_audited` asserts
exact payload byte sizes (15 / 11) — the fix must not change any
single-fd behavior, so those assertions must be untouched; if
they start failing, investigate before adjusting them.

## 8. Scope / non-goals

- Touch only `forward()` in `src/proxy/mod.rs` and
  `tests/proxy_integration.rs`. Do **not** modify `clipboard.rs`,
  `audit.rs`, the broker, or the `wire.rs` codec.
- Do not change the audit record shape or the N-D-JSON broker
  protocol.
- After landing: delete the "Critical (open defect)" section in
  `TASKS.md`, delete the pointer in `AGENTS.md`, and delete this file
  (or keep it as a post-mortem — ask the user).
- Commit style follows the repo convention `apse: <what>` (the
  landed subject is in the header).

## 9. Key locations (HEAD `fa4eee8`)

All cited inline above: `src/proxy/mod.rs` — `forward`
(~628–642), `recv` (~230), `pump` (~549), `out_fds` rebuild +
`dst.send` (~1000–1015); `src/proxy/wire.rs` — `parse_message`
(~105–125); `tests/proxy_integration.rs` — fake data-device
compositor harness (1030), `Srv2::request` (~966–1028), single-fd
precedent test (635); registry
`wayland-backend-0.3.11/src/rs/socket.rs:38,152`.

## 10. Related, separate issue from the same review — do not bundle

`start_drag` pending latch (`src/proxy/clipboard.rs`): if the app
starts a drag with its own source but the compositor never sends the
matching `enter` event (drag rejected / non-ordinary teardown),
`pending` stays set and a later *foreign* `data_offer` is attributed
`own`, bypassing the deny gate. Proposed guard: clear
`pending`/`pending_psel` on the fatal/teardown paths, and (stronger)
scope the `own` attribution to the client that set the pending. First
confirm wlroots' behavior for a rejected `start_drag` (its source was
not reachable during the review — GitLab is bot-walled). Track as its
own task; do not mix it into the fd fix commit.
