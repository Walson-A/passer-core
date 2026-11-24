# Integrating passer-core in your app

Can another developer build on passer-core today? **For experiments, yes. For a product
shipped to users, not yet.** This page says what works, what is missing, and in which order
it will come.

## What you can do today

- **Rust apps** (desktop with Tauri, a daemon, a CLI): depend on the crates by git URL.

  ```toml
  [dependencies]
  passer-ffi = { git = "https://github.com/Walson-A/passer-core", rev = "<commit>" }
  ```

  `passer_ffi::PasserDevice` is the simplest entry point (the same one the mobile apps use).
  For full control, use `passer-node` (a running device), `passer-bus` (your own modules)
  and `passer-membership` (groups and invitations) directly.

- **Write a module**: implement `passer_bus::Module` (declare capabilities, implement
  `invoke`). See `crates/passer-device-info` for the smallest example. The bus does the
  permission checks, approvals, sessions and journal; your code only does the work.

- **iOS, macOS (Swift) and Android (Kotlin)**: generate the bindings yourself (see
  [`platforms.md`](platforms.md)), build the library for your targets, and implement the
  three callbacks (`KeyVault`, `ApprovalPrompter`, `CapabilityHandler`).

- **AI agents**: run `passer-core mcp` and grant capabilities with `passer-core grant`.

- **A devices screen**: `members()` returns each member with what it last said about itself
  (kind, OS and version, app version, when it last answered); declare your own with
  `set_device_details` before `start`. `member_capabilities(device)` lists what a member lets
  you call and which of it needs approval, to make buttons. `journal_recent(limit, device)`
  is the history with one member (calls made and received, never their content). Call
  `refresh_members()` after a device joins or when the app returns to the foreground.

## What is missing before a third party should ship on it

| Missing | Why it matters | Plan |
|---|---|---|
| A stable API (still 0.x) | the protocol and the types will change; apps built today will break | freeze the wire protocol and the `passer-ffi` surface, then semantic versioning |
| Published packages | no crates.io release, no Swift Package / XCFramework, no Android AAR on Maven | release builds of `passer-ffi` with the generated bindings for each platform |
| An external security audit | the code was reviewed, not audited | required before 1.0 |
| Streams | no large file transfer through the bus yet | next feature of the core |
| Push notifications | a sleeping phone cannot be reached or asked to approve | with the mobile integration |
| A production relay and coordination server you can use | the CLI's `n0` mode uses n0's development relays | self-host `passer-coord` and `iroh-relay`, or use Passer's service when it exists |
| Documentation for integrators | this page, the crate docs and the tests are all there is | API docs and a sample app with the first release |

## Rules for anyone building on it

- Never ask the user for the pairing link's secret in any other way than the QR code or the
  link itself, and never log it.
- Show the 6-digit code at pairing on both devices; tell users to cancel if they differ.
- Show a short device id next to device names in anything security-relevant (approvals,
  device lists).
- Treat everything that comes from another device — names, titles, outputs — as untrusted
  text: display it, never execute it, never pass it to an agent as an instruction.
