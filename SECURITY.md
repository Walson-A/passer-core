# Security policy

passer-core decides which devices may talk to each other and what they may do. A flaw here
can expose people's files, clipboard or screen, so reports are taken seriously.

## Reporting a vulnerability

- **Do not open a public issue.**
- Use GitHub's private vulnerability reporting: *Security → Report a vulnerability* on this
  repository.
- Include what you found, how to reproduce it, and what an attacker gains.

You will get an acknowledgement within 7 days. Fixes for confirmed issues are released as
soon as possible, and you will be credited unless you prefer not to be.

## Scope

In scope: everything in this repository — identity, the device log and pairing, the
transport integration, the capability bus (policy, approvals, leases, journal), the CLI.

Out of scope: iroh itself (report to [n0](https://github.com/n0-computer/iroh/security)),
n0's public relays, and modules that live in other repositories.

## Supported versions

The project is a prototype (0.x). Only the latest commit on `main` receives fixes.

## Before a public release

The project commits to an external security audit before any release meant for the
general public. The threat model is in [`docs/security.md`](docs/security.md).
