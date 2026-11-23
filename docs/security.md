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
| Relay or coordination server (compromised, compelled, or careless) | read content; add a device | end-to-end encryption; **signed device log**: only an approver key can add a device | in place (no server exists yet; the log already enforces it) |
| | withhold or roll back updates | a device refuses any log that does not extend the one it holds | in place for what the device has seen |
| Intercepted pairing (QR photographed, link leaked) | join the group | 256-bit one-time secret, ≤ 15 min; MAC + signature bound to the joiner's authenticated key; 6-digit SAS to compare | in place; PAKE for short typed codes planned |
| Lost or stolen device | keep using its access | removal by any approver; revoked keys can never be re-added; leases of a removed device are revoked | in place; propagation is pull-based (`sync`) |
| Compromised device | act with its rights | out of reach of any protocol; damage limited by per-device rules and approvals on the target | partial |
| Manipulated AI agent | read data, send it elsewhere | agents denied by default; agent rules can be pinned to the relaying device; no capability in the core sends outside the group | in place in the bus; bridge not built |
| Other member device | impersonate an agent's grants | `Who::Agent { via }` pins a grant to the bridge device | in place |
| Replay / downgrade | reuse a request or signature | context-separated signatures; one-time invitations; versioned ALPNs and links | in place |
| Supply chain | poisoned dependency | locked dependencies, `cargo-deny` policy, few dependencies in the trust core | config in repo; CI planned |

## Principles

1. **Keys are generated on the device and never leave it.** The id is the public key.
2. **End-to-end:** neither relay nor coordination server can read anything.
3. **The server cannot add a device:** the membership log is signed by existing approvers
   and verified by every device.
4. **No home-made cryptography:** Ed25519 and TLS 1.3 come from iroh / RustCrypto, hashing
   from BLAKE3. The only custom format is the signed device log — small, documented,
   tested, and the first thing an audit should read.
5. **Revocation is final** and interrupts running sessions.
6. **Sensitive capabilities ask on the target, run with a visible indicator, in a bounded
   session** that a stop button or physical input can cut.
7. **Local journal** of every call, hash-chained, without content.

## Known gaps of the prototype

Be explicit about these before anyone relies on the code:

- **Keys are in a plain file** (`FileKeyStore`). Platform vaults (Keychain `ThisDeviceOnly`,
  DPAPI/TPM, Android Keystore) are not implemented.
- **No hardware-bound root key.** The Secure Enclave and TPMs generally offer P-256, not
  Ed25519, while iroh's identity is Ed25519; the plan is a non-extractable P-256 root key
  that signs a rotatable Ed25519 transport key. Not designed in detail yet.
- **No key rotation and no account recovery.** If every approver is lost, the group cannot
  be managed. A printed recovery code is planned; the server must never be able to recover
  on its own.
- **Log updates are pulled**, not pushed: an offline device learns about a removal only when
  it syncs. A device that never saw an update cannot detect that it is being withheld.
- **The journal** detects edits and deleted lines in the middle, not truncation of its tail
  or deletion of the whole file by someone with disk access.
- **Join attempts are not rate-limited.** The secret is 256 bits (no brute force), but a
  flood is a denial-of-service vector.
- **Approvals** have an interface only (`Approver`); routing to a phone is not built, so the
  default answer to `ask` is *no*.
- **Streams are not implemented**; long-running modules must honour their lease themselves.
- **n0's public relays** are used by the CLI's default network mode: development only.
- **No fuzzing yet.** Planned `cargo-fuzz` targets: invitation links, frames, the device log
  (JSON and verification), join requests, capability schemas.
- **No external audit yet.** Required before any public release.
