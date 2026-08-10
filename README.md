# GMA Auth Module

This repository owns the optional GMA Auth module: password and multi-provider identities, safe account linking, email verification, enumeration-safe password recovery, authentication assurance and password step-up, optional TOTP authentication with one-time recovery codes, session security, JWT integration, admin member management, provider-split persistence, and auth integration events.

It is consumed by source-first applications and by the `GMA-Skeleton` composition repository as a Git submodule under `gma/modules/auth`.

Useful entry points:

- `Gma.Modules.Auth.slnx`
- `docs/README.md`

The core remains provider-neutral. `Gma.Modules.Auth.Providers.OpenIdConnect` is an optional adapter for Google, Microsoft, and other standards-compliant OpenID Connect providers, including browser-safe challenge handoffs for scope-aware applications. Applications that also install Notifications can opt into the composition-owned `Gma.Extensions.Auth.Notifications` bridge without coupling either module to the other. Trusted in-process orchestrators can separately opt into the Contracts-only subject-status reader; ordinary Auth composition does not expose this subject-status capability.
