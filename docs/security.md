# Security model

Security is the first priority of passer-core. This document says what is protected,
against whom, how — and, just as plainly, what the prototype does **not** protect yet.

## Assets

The content devices exchange (files, clipboard, screen), the ability to act on a device
(inputs, capabilities), the list of a person's devices, and the device keys.

## Adversaries and defences

| Adversary | Tries to | Defence | Status |
|---|---|---|---|
| Network observer (public Wi-Fi, ISP) | read or alter traffic | QUIC / TLS 1.3 with raw public keys (iroh); no cleartext mode in the core | in place |
| Relay or coordination server (compromised, compelled, or careless) | read content; add a device | end-to-end encryption; **signed device log**: only an approver key can add a device | in place |
| | withhold or roll back updates | devices and server keep the log the fork-choice rule prefers; a shorter history never replaces a longer one | in place for what a device has seen |
| Removed (e.g. stolen) approver | keep control by publishing a fork made before its removal | **fork choice: revocation wins**; a removal is never dropped for a branch that removes less; the losing device replays its own entries on the winner; every device and the server converge on the same branch | in place |
| Intercepted pairing (QR photographed, link leaked) | join the group | 256-bit one-time secret, ≤ 15 min; MAC + signature bound to the joiner's authenticated key; 6-digit SAS to compare | in place; PAKE for short typed codes planned |
| Joining device | pass for another device by name | names unique in the group (case, spaces and punctuation ignored); invisible and bidirectional characters refused; ids shown in approval prompts | in place; look-alike letters from other scripts are not caught |
| Lost or stolen device | keep using its access | removal by any approver; revoked keys never come back; its sessions are revoked and its open connections closed | in place |
| Compromised device | act with its rights | out of reach of any protocol; damage limited by per-device rules and approvals on the target | partial |
| Malicious member | spam approval prompts, inject text into them | one pending prompt per device, 6 per minute; all prompt strings stripped of control, invisible and bidi characters and bounded | in place |
| | poison an MCP tool's description or effect | one MCP tool per distinct declaration; one device's declaration never describes another's | in place |
| Manipulated AI agent | read data, send it elsewhere | agents denied by default; grants pinned to the relaying device; no capability in the core sends outside the group | in place |
| Replay / downgrade | reuse a request or signature | context-separated signatures; one-time invitations; versioned ALPNs and links | in place |
| Resource exhaustion | memory, CPU, tasks | frames ≤ 1 MiB read incrementally with a 15 s timeout; logs ≤ 4096 entries; server checks signatures off-lock on blocking threads, per-group locks, ≤ 100 000 groups | partial (no rate limiting of joins and publishes yet) |
| Supply chain | poisoned dependency | locked dependencies, `cargo-deny` policy, few dependencies in the trust core | config in repo |

## Principles

1. **Keys are generated on the device and never leave it.** The id is the public key.
2. **End-to-end:** neither relay nor coordination server can read anything.
3. **The server cannot add a device:** the membership log is signed by existing approvers
   and verified by every device.
4. **No home-made cryptography:** Ed25519 and TLS 1.3 come from iroh / RustCrypto, hashing
   from BLAKE3. The only custom formats are the signed device log and its fork-choice rule —
   small, documented, tested, fuzzed, and the first thing an audit should read.
5. **Revocation is final**, wins forks, interrupts running sessions and closes connections.
6. **Sensitive capabilities ask on the target, run with a visible indicator, in a bounded
   session** that a stop button or physical input can cut.
7. **Local journal** of every call, made or received, hash-chained, without content; every
   string printable.
8. **What members say about themselves is display only:** `device.info` answers are bounded,
   sanitized and never used for a decision, and a background refresh never triggers an
   approval prompt on another device.

## Testing

- Unit and end-to-end tests over real QUIC connections, on Linux, Windows and macOS (CI).
- Property tests (proptest): random byte mutations of a signed log never yield a different
  valid membership; reordered, dropped or duplicated entries never verify as new state;
  link, request and policy parsers never panic; the bus never runs a module on input that
  does not match its schema, nor a sensitive capability without approval.
- Fuzzing (cargo-fuzz, `fuzz/`): invitation links, device logs (decode, verify, fork choice),
  wire messages. A short run happens on every push in CI; run longer with
  `cargo +nightly fuzz run <target>`.
- Concurrency: simultaneous joins, simultaneous calls, removal during a call and during a
  pending approval, forks resolved and replayed.
- Fork choice: antisymmetric on random forks (property test), so every party converges;
  a removal is kept over a branch that removes less; the losing side replays its removals.

## Security review of 23 November 2026

An independent review (separate from the author of the code) reported 12 findings. Status:

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | A removed approver could keep the group by publishing a pre-removal fork first | high | fixed: fork choice (`DeviceLog::prefer`), used by devices and server, plus replay of the losing side's own entries; tests reproduce the attack end to end. Follow-up from the reviewer: a removal could be dropped for a branch adding a device — fixed (removals are never dropped for a branch that removes less) |
| 2 | Any member could show forged approval prompts with terminal escape sequences | medium | fixed: strings sanitized, ids shown, prompts rate-limited, one terminal reader |
| 3 | Duplicate and look-alike device names | medium | fixed for case/spacing/punctuation and invisible/bidi characters; cross-script look-alikes remain (ids shown) |
| 4 | A member could poison another device's MCP tool metadata | medium | fixed: one tool per distinct declaration, unique tool names |
| 5 | Unbounded agent string; removed devices kept their connections | medium/low | fixed: agent names ≤ 64 safe characters; connections closed on removal |
| 6 | Server did expensive verification under a global lock; unbounded groups | medium | fixed: off-lock verification, per-group locks, log and group caps |
| 7 | Removal during a pending approval still granted a session | low | fixed: membership re-checked after approval |
| 8 | No frame timeouts; length pre-allocated | low | fixed: timeouts, incremental reads, bounded waits |
| 9 | A removed device kept learning the membership | low | fixed: it receives the log only up to its removal |
| 10 | Address hints could erase good addresses | low | fixed: addresses are merged, not replaced |
| 11 | Concurrent saves could corrupt the group file | low | fixed: atomic writes under the lock, unique temporary files |
| 12 | Unbounded lease length; invitation burnt by a bad name | info | fixed: leases ≤ 1 day (15 min if sensitive); names checked before consuming |

## Known gaps of the prototype

- **Key storage.** On Windows the key is encrypted with DPAPI (`DpapiKeyStore`, current
  user, extra entropy): useless on another machine or account, but readable by malware
  running as the same user. Elsewhere it is a plain file (`FileKeyStore`) unless the app
  provides a `KeyVault` (Keychain `ThisDeviceOnly`, Android Keystore). TPM is not used yet.
- **No hardware-bound root key.** The Secure Enclave and TPMs generally offer P-256, not
  Ed25519, while iroh's identity is Ed25519; the plan is a non-extractable P-256 root key
  that signs a rotatable Ed25519 transport key. Not designed in detail yet.
- **No key rotation and no account recovery.** If every approver is lost, the group cannot
  be managed. With only two approvers that remove each other, the fork-choice rule falls
  back on seniority (the older device wins). A compromised approver that acts *before* it is
  removed, and whose changes other devices have already adopted, can lock them out. Keep at
  least three approvers; a printed recovery code is planned.
- **Log updates** travel through the coordination server or a peer when a device syncs
  (every 30 s). A device that never saw an update cannot detect that the server withholds
  it; gossip between devices would reduce this. The server sees metadata (keys, device
  names, IPs, online times). No rate limiting of joins and publishes yet.
- **Fork choice with three or more concurrent branches** is decided pairwise; the rule is
  antisymmetric (tested) but its transitivity across many branches is not proven.
- **Look-alike names** from other scripts (Cyrillic "РС" vs Latin "PC") are not caught;
  apps should show a short id next to names.
- **The journal** detects edits and deleted lines in the middle, not truncation of its tail
  or deletion of the whole file by someone with disk access.
- **Approvals do not reach a sleeping phone** (needs push notifications).
- **Streams are not implemented**; long-running modules must honour their lease themselves.
- **Agent identity is asserted by the bridge device.** A grant pinned with `via` only trusts
  that device's claim. The hosted MCP service (OAuth, per-agent consent) is not part of this
  repository.
- **The MCP bridge and `serve` use the same device key** when run side by side on one device:
  both work for outgoing calls, but incoming calls reach only one of them.
- **n0's public relays** (CLI default network mode) are for development only. In that mode
  the device's relay is published to n0's DNS: anyone who knows a device id can see when it
  is online and which relay it uses.
- **No external audit yet.** Required before any public release.
