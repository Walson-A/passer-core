# Running your own relay and coordination server

Devices on the same network reach each other directly. Away from home (a phone on 5G, a
laptop at work), they need two small services, which you can run yourself:

| Service | What it does | What it sees |
|---|---|---|
| **Relay** (`iroh-relay`, by n0) | Forwards encrypted packets between devices that cannot connect directly, and helps them find a direct path (most connections end up direct). | Encrypted bytes and device ids. Never content: connections are end-to-end encrypted between devices. |
| **Coordination server** (`passer-coord`) | Keeps each group's latest device log (so additions and removals reach devices that were offline) and where each device was last seen. | Which keys form a group, device names, IP addresses, when devices come online. It cannot add a device: it has no approver key. |

Without them, use `--network n0` (n0's public relays) for development only, or stay on one
network with `--network local`.

## With Docker

On a machine with a public IP and a domain name pointing at it:

```sh
git clone https://github.com/Walson-A/passer-core
cd passer-core/deploy
# edit relay.toml: your domain and e-mail, then
docker compose up -d --build
docker compose logs coord
```

The last command prints the coordination server's id. It is the server's public key: devices
pin it, so keep the `coord-data` volume (it holds the key).

Open these ports: **80/tcp and 443/tcp** (relay, Let's Encrypt), **7842/udp** (QUIC address
discovery), **4433/udp** (coordination). In `relay.toml`, set `prod_tls = true` once the
staging certificate works.

## Without Docker

```sh
cargo install iroh-relay@1.5.0 --features server --locked
iroh-relay --config-path relay.toml

cargo build --release -p passer-coord
./target/release/passer-coord --home ./coord --port 4433
```

## Pointing devices at them

Command line:

```sh
passer-core --network relay --relay https://relay.example.com \
            --coord <server id>@coord.example.com:4433 serve
```

(`PASSER_CORE_RELAY` and `PASSER_CORE_COORD` work too.)

Apps, through `passer-ffi`:

```rust
device.start(NetworkKind::Relay { url: "https://relay.example.com".into() },
             Some("<server id>@coord.example.com:4433".into())).await?;
```

Invitations then carry the relay's address, so a device can join from anywhere; the
coordination server tells each device where the others are.

## Limiting who uses your relay

Relaying costs bandwidth. `relay.toml` can restrict it to your devices' ids
(`access.allowlist`), or to holders of a token (`access.shared_token`). See the comments in
`deploy/relay.toml` and iroh-relay's documentation.

## What is not here yet

- One server for many users (accounts, quotas): the code supports many groups per server
  (`MAX_GROUPS`), not billing or abuse handling.
- A push gateway. To wake sleeping phones, run one next to the server and start it with
  `passer-coord --wake-url http://gateway:8080/wake --wake-secret <secret>`
  (`PASSER_COORD_WAKE_URL`, `PASSER_COORD_WAKE_SECRET`). The gateway receives
  `POST {"token": "...", "group": "..."}` and sends a silent push with your Apple or Google
  credentials. See `docs/integrating.md`.
