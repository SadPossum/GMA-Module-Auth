# GMA Auth Module

This repository owns the optional GMA Auth module: password and multi-provider identities, safe account linking, email verification, session security, JWT integration, admin member management, provider-split persistence, and auth integration events.

It is consumed by source-first applications and by the `GMA-Skeleton` composition repository as a Git submodule under `gma/modules/auth`.

Useful entry points:

- `Gma.Modules.Auth.slnx`
- `docs/README.md`

The core remains provider-neutral. `Gma.Modules.Auth.Providers.OpenIdConnect` is an optional adapter for Google, Microsoft, and other standards-compliant OpenID Connect providers. Auth security and verification messages are delivered by the optional Notifications-owned `Gma.Modules.Notifications.Integrations.Auth` bridge.
