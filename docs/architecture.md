# Architecture

passer-core is a **bus**: identity, pairing, transport, and a generic way to declare and
invoke capabilities, with one permission checkpoint. What devices actually do lives in
**modules** on top. Rule for what enters the core: *every module needs it, and the security
of the whole depends on it.* Anything else is a module, often in its own repository.

```text
 Bridges     MCP (planned) · app intents · CLI
 Modules     device-info (example, here) · transfer (Passer) · screen (separate project)
 L3 Bus      declare · validate · policy · approve · indicator · lease · journal
 L2 Node     iroh endpoint (key = device), ALPNs: bus / log / join
 L1 Members  signed device log · invitations · revocation
 L0 Identity Ed25519 key per device, kept by a KeyStore
```

## L0 — Identity (`passer-identity`)

- A device's id is its Ed25519 public key, the same key iroh uses as `EndpointId`. The
  transport therefore authenticates exactly the key the membership log names.
- Every signature carries a context string (`membership/entry/v1`, `membership/join/v1`)
  and is length-framed, so no signature can be replayed for another purpose.
- `KeyStore` abstracts where the private key lives. Only `FileKeyStore` (development) exists
  today; platform vaults are planned (see `security.md`).

## L1 — Membership (`passer-membership`)

The group **is** its `DeviceLog`: an append-only list of entries, each with a sequence
number, the hash of the previous entry, the author's id, an operation and the author's
signature.

| Operation | Who may write it |
|---|---|
| `genesis { group, device_name }` | the founder, first entry only; becomes the first approver |
| `add { device, name, approver }` | an approver |
| `remove { device }` | an approver, or the device itself |

Rules: a removed key is revoked forever; the last approver cannot be removed; names are
1–64 bytes without control characters. `verify()` replays the whole chain; any forged,
re-signed, reordered or edited entry is rejected. `accept_update()` adopts a received log
only if it extends the one already held (refusing rollbacks and forks).

**Forks.** Two valid branches can exist (two approvers writing at once, or a removed
approver publishing a branch made before its removal). `DeviceLog::prefer` picks one, the
same way on every device and on the server: revocation wins (a branch that removes the
other branch's authors), then the branch keeping more approvers from the fork point, then
the more senior device, then the lower digest. Names must be unique in a group (ignoring
case, spaces and punctuation) and free of invisible or bidirectional characters. Logs are
capped at 4096 entries.

**Consequence:** whoever stores and relays the log — a coordination server, another device
— cannot add a device. It has no approver key to sign with.

### Pairing

1. An approver issues an `Invitation`: a 256-bit one-time secret, valid ≤ 15 minutes, plus
   its id and direct addresses, as a link `passer-core://join?v=1&g=…&i=…&s=…&e=…&a=…`
   (shown as a QR code by apps). The link contains the secret.
2. The new device sends a `JoinRequest` on the join ALPN: its id and name, a BLAKE3 MAC keyed
   by the secret, and a signature by its own key.
3. The inviter checks: the request's id equals the key the transport authenticated; the
   signature; the MAC (constant-time) against pending invitations; expiry. The invitation
   is consumed, and the inviter appends a signed `add`.
4. Both sides can show the same 6-digit SAS derived from the secret and both keys.

## L2 — Node and transport (`passer-node`)

One iroh endpoint per device, keyed by its identity. Three protocols, one ALPN each:

| ALPN | Who may connect | What happens |
|---|---|---|
| `passer-core/bus/1` | members only (checked at accept, then again per request) | one request/response per bidirectional stream |
| `passer-core/log/1` | members only | returns the current device log |
| `passer-core/join/1` | anyone | redeems an invitation, or nothing |

Frames are a 4-byte big-endian length (≤ 1 MiB, checked before allocating) followed by
JSON. Network modes: `LocalOnly` (direct addresses, used by tests) and `N0Dev` (n0's public
relays and address lookup — development only; production will run its own `iroh-relay`).

## L3 — Capability bus (`passer-bus`)

A `Capability` declares `name`, `title`, `description`, `input_schema` (JSON Schema),
optional `output_schema`, `effect` (`read` / `write` / `sensitive`), `mode` (`call` /
`stream`), optional `target_kind` (e.g. `app`) and an `indicator` requirement.

`Bus::handle(subject, request)` runs, in order:

1. **membership** of the authenticated device;
2. **lookup**, target consistency, **schema validation** (no remote `$ref` resolution);
3. **policy**: ordered rules `(who, capability pattern, target) → allow | ask | deny`, with
   a lease length. Defaults: member devices may read and write; sensitive asks; agents get
   nothing unless granted. Sensitive leases are capped at 15 minutes;
4. **approval** (`Approver`, 60 s timeout) when the decision is `ask`;
5. **indicator**: a capability that requires one does not run without an `Indicator`, which
   is shown for the lease's lifetime;
6. **lease**: the module runs inside a `LeaseHandle` the device can suspend (e.g. physical
   input) or revoke (stop button, device removed); revocation interrupts the call;
7. **journal**: one hash-chained line, never the input or output.

`bus.capabilities` (built in) lists what the caller may invoke — the basis of the MCP bridge.

### Approvals (`passer-node::approval`)

When the policy says `ask`, `RemoteApprover` asks in parallel the target device's own user
(a local `Prompter`) and every other **approver** device, through their `approval.request`
capability (`ApprovalModule`). The first answer wins; nobody reachable means *no*. The
requesting device is never asked — a request cannot approve itself — and the prompt shows
names taken from the approver's own membership log. Invitations decide the role of the
device that joins (`invite_approver`); the joining device cannot change it.

## Server half — coordination (`passer-coord`)

One protocol, `passer-core/coord/1`, one message: a device publishes its device log and its
direct addresses; the server answers with the group's current log and the presence of the
other members seen in the last 5 minutes.

- The server keeps, per group, whichever log **extends** the other; it refuses logs that do
  not verify and forks of the history it holds. It cannot write a log entry itself.
- It answers only devices that are members of the log it holds. A removed device is told it
  was removed (and gets the log that says so), nothing else.
- The device adopts the returned log only if it is a valid extension of its own
  (`Node::adopt_log`) and remembers addresses only for members of its own verified log.
- What the server sees: the group's public keys and device names, IP addresses, online
  times. Never content. A relay (`iroh-relay`, a standard n0 binary) is deployed next to it.

The same crate serves Passer's hosted service (many groups) and a self-hosted engine (one
group). Accounts, quotas, billing and abuse handling belong to the hosted service, not here.

## MCP bridge (`passer-mcp`)

A bridge device serves MCP over stdio to a local agent client. `tools/list` asks every other
member which capabilities it grants this agent (`bus.capabilities` with the agent's name)
and turns each `call` capability into a tool (`device.info` → `device_info`) with a `device`
argument listing the devices that offer it (and `target` when the capability has one).
Annotations follow the effect: `read` → read-only; `write` and `sensitive` → destructive,
so clients confirm. `tools/call` forwards the call labelled with the agent's name. The
bridge decides nothing: policy, approval, indicator, lease and journal happen on the device
that acts. Agents are denied by default; `grant` adds a rule `Who::Agent { name, via }`
pinned to the bridge device.

## Planned next

- Streams (file transfer) on the bus; video stays WebRTC in the screen project, with the
  bus for identity, permission and signalling.
- Platform key stores, hardware-bound root key; UniFFI bindings for iOS and Android.
- Push notifications so approvals reach a sleeping phone; push of log updates (today:
  pull with `sync`).
