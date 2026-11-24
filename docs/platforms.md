# Platforms

passer-core is a library, not an app. People install **an app** (Passer, Atlas…) on each of
their devices, and the app embeds the core. The same Rust code runs everywhere; only the
thin layer that talks to the operating system differs.

| Platform | How the core is embedded | Key storage | Status |
|---|---|---|---|
| **Windows** | Rust, directly (Tauri desktop app, CLI) | DPAPI (`DpapiKeyStore`) | builds and tested in CI |
| **macOS** | Rust, directly (Tauri desktop app, CLI); or Swift through `passer-ffi` | Keychain (`KeyringKeyStore`), or `KeyVault` from Swift | builds and tested in CI |
| **Linux** | Rust, directly (Tauri desktop app, CLI, headless daemon) | Secret Service (`KeyringKeyStore`); an owner-only file without one (headless) | builds and tested in CI |
| **iOS / iPadOS** | Swift bindings of `passer-ffi` (UniFFI), wrapped in an Expo module for the React Native app | Keychain `ThisDeviceOnly`, implemented by the app as `KeyVault` | library builds in CI for `aarch64-apple-ios` and the simulator |
| **Android** | Kotlin bindings of `passer-ffi` (UniFFI), wrapped in an Expo module | Keystore-wrapped storage, implemented by the app as `KeyVault` | library builds in CI for `aarch64-linux-android` |

## The app-facing API (`passer-ffi`)

One object, `PasserDevice`:

```swift
let device = try PasserDevice(home: appSupportDir, vault: KeychainVault())
if !device.hasGroup() {
    let joined = try await device.join(link: scannedQr, deviceName: "iPhone", network: .localOnly)
    // show joined.sas next to the code on the PC
}
device.addCapabilities(specs: [clipboardRead], handler: ClipboardHandler())
device.setApprovalPrompter(prompter: ApprovalSheet())
try await device.start(network: .localOnly, coord: "<id>@<ip:port>")
let info = try await device.call(device: "PC", capability: "device.info", inputJson: "{}")
```

The app implements three callback interfaces natively:

- `KeyVault` — `load()` / `store(secret)`: where the 32-byte device key lives. The key is
  generated in Rust and handed to the vault once.
- `ApprovalPrompter` — `ask(request) async -> Bool`: a sheet or a notification. Called when
  this device must approve something, or when it is an approver for another device.
- `CapabilityHandler` — `invoke(capability, target, inputJson, caller) async -> String`:
  what the device actually does. It runs only after the bus has checked membership, input
  schema, policy, approval, indicator and session; the call is journaled either way.

Errors arrive as a typed `PasserError` (`NoGroup`, `NotStarted`, `Refused { code }`…).

## Generating the bindings

```sh
cargo build -p passer-ffi --release
cargo run -p uniffi-bindgen -- generate --library target/release/<lib> --language swift  --out-dir bindings/swift
cargo run -p uniffi-bindgen -- generate --library target/release/<lib> --language kotlin --out-dir bindings/kotlin
```

`<lib>` is `libpasser_ffi.dylib` (macOS), `libpasser_ffi.so` (Linux) or `passer_ffi.dll`
(Windows). For iOS, build the static library for `aarch64-apple-ios` and
`aarch64-apple-ios-sim` and package both with the generated header as an XCFramework;
for Android, build with `cargo ndk` for each ABI and put the `.so` files in `jniLibs/`.

## Phones: what the operating system allows

- **iOS suspends apps in the background**: a connection lives about 30 seconds after the
  app leaves the screen. An iPhone is therefore mostly a *caller* and an *approver*; it
  serves capabilities while the app is open. Reaching a sleeping iPhone needs a push
  notification (planned), which wakes the app or shows the approval.
- **Local network access** on iOS needs the user's permission (`NSLocalNetworkUsageDescription`);
  connecting through a relay or a coordination server does not.
- **Android** allows a foreground service for longer sessions, at the cost of a permanent
  notification; the same API applies.
