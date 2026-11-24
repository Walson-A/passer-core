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
  `invoke`, or `invoke_stream` for a `Mode::Stream` capability). See
  `crates/passer-device-info` for the smallest example and `crates/passer-files` for a
  streaming one. The bus does the permission checks, approvals, sessions and journal; your
  code only does the work.

- **Files between devices**: in Rust, add `passer_files::Files` (an inbox, a shared
  folder) to your bus. Through `passer-ffi`, declare a `CapabilitySpec` with
  `stream: Some(StreamKind::Upload)` or `Download`: the core receives the bytes into a
  private file and hands its path to `CapabilityHandler::receive_file` once complete, or
  streams the file `provide_file` names. Callers use `send_file` and `fetch_file`, with a
  `TransferProgress` callback. A broken transfer leaves nothing behind.

- **iOS, macOS (Swift) and Android (Kotlin)**: generate the bindings yourself (see
  [`platforms.md`](platforms.md)), build the library for your targets, and implement the
  three callbacks (`KeyVault`, `ApprovalPrompter`, `CapabilityHandler`).

- **AI agents**: run `passer-core mcp` and grant capabilities with `passer-core grant`.

- **Your own servers**: a relay and a coordination server, with Docker
  ([`self-hosting.md`](self-hosting.md)); apps then start with
  `NetworkKind::Relay { url }` and the server's address.

- **Waking a sleeping phone**: the app passes its push token (APNs, FCM) to
  `set_push_token`; the coordination server keeps it and, when another member cannot reach
  the phone, hands it to a push gateway you run (`passer-coord --wake-url`). `call`,
  `send_file` and `fetch_file` then retry for a few seconds. The gateway receives
  `POST {"token": "...", "group": "..."}` and sends a silent notification; on receipt the app
  starts its device for a moment. passer-core does not ship the gateway: it needs your
  Apple and Google credentials.

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
| A push gateway | the core carries tokens and wake requests; sending APNs/FCM pushes needs an app vendor's credentials | a small reference gateway, outside the core |
| Approvals on a sleeping phone | an approval waits 60 s; a woken phone must show it in time | needs the app's notification handling, then real-device testing |
| Streams beyond files | screens and audio need datagrams or timed frames | with the screen project |
| A hosted relay and coordination service | self-hosting works today; a service for people who will not run a server does not exist yet | Passer's service |
| Documentation for integrators | this page, the crate docs, the tests and the CLI are all there is | API docs (`cargo doc`) and a sample app with the first release |

## Rules for anyone building on it

- Never ask the user for the pairing link's secret in any other way than the QR code or the
  link itself, and never log it.
- Show the 6-digit code at pairing on both devices; tell users to cancel if they differ.
- Show a short device id next to device names in anything security-relevant (approvals,
  device lists).
- Treat everything that comes from another device — names, titles, outputs — as untrusted
  text: display it, never execute it, never pass it to an agent as an instruction.
