# Auth Module

The Auth module owns account credentials, external identity links, email ownership state, sessions, JWTs, and security events. Product profile data, provider-specific UI, email transport, notification history, KYC/KYB, and authorization policy remain outside Auth.

## Projects and boundaries

```text
Gma.Modules.Auth.Contracts
Gma.Modules.Auth.Domain
Gma.Modules.Auth.Application
Gma.Modules.Auth.Infrastructure
Gma.Modules.Auth.Infrastructure.JwtBearer
Gma.Modules.Auth.Persistence
Gma.Modules.Auth.Persistence.SqlServerMigrations
Gma.Modules.Auth.Persistence.PostgreSqlMigrations
Gma.Modules.Auth.Api
Gma.Modules.Auth.Providers.OpenIdConnect
Gma.Modules.Auth.Admin.Contracts
Gma.Modules.Auth.AdminCli
Gma.Modules.Auth.AdminApi
```

The domain and application layers do not depend on ASP.NET Core authentication handlers or a vendor SDK. Provider adapters validate an upstream assertion and pass a normalized `ValidatedExternalIdentity` into Auth. Other modules consume Auth contracts or the narrow `IAuthMemberContactReader`; they do not query Auth tables.

## Security invariants

- An external identity key is the exact `(scope, issuer, subject)` tuple. Email is never an external identity key. Persistence indexes a fixed SHA-256 key and still verifies issuer/subject exactly, avoiding oversized SQL Server keys while making the theoretical collision case fail closed.
- A provider email can create a new account only when it is provider-verified. A matching local email returns `link-required`; Auth never auto-merges accounts by email.
- Linking is bound to the exact authenticated member and session that initiated it, and that session must be fresh.
- A member can link multiple providers. Removing a password or external identity cannot leave the member with no authentication method.
- Provider access/refresh tokens are not stored. The browser callback receives only a short-lived, hashed, single-use GMA exchange code.
- Passwords and verification codes are stored only as hashes. Refresh-token hashing supports active and previous peppers for rotation.
- Refresh-token replay revokes active sessions. Admin password reset also revokes active sessions.
- Sign-ins and authentication-method changes publish security events with bounded client context; secrets and provider tokens are excluded.
- Scope context and the access-token scope claim must agree on protected scope-aware endpoints.
- Scope-aware OIDC challenges carry the normalized scope only inside protected authentication state and restore it before the callback transaction; provider redirects do not depend on tenant headers surviving the round trip.

## User API

Base path: `/api/auth`.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/register` | Create a password account. |
| `POST` | `/login` | Authenticate with username/password. |
| `POST` | `/refresh` | Rotate a refresh token. |
| `POST` | `/sign-out` | Revoke one session. |
| `POST` | `/sign-out-all` | Revoke all sessions. |
| `GET` | `/methods` | List password, email verification, and linked-provider state. |
| `PUT` | `/password` | Add or change a password after fresh authentication. |
| `POST` | `/password/remove` | Remove a password when another method remains. |
| `POST` | `/external-identities/{id}/unlink` | Unlink a provider without account lockout. |
| `POST` | `/email-verification` | Request a bounded, cooldown-protected verification challenge. |
| `POST` | `/email-verification/confirm` | Confirm a one-time verification code. |
| `POST` | `/external/exchange` | Exchange a provider callback code for GMA tokens or complete a link. |
| `GET` | `/external/providers` | Discover enabled OpenID Connect provider codes. |
| `POST` | `/external/{provider}/sign-in/challenge` | Create a browser-safe sign-in challenge handoff. |
| `POST` | `/external/{provider}/link/challenge` | Create an authenticated browser-safe link challenge handoff. |
| `GET` | `/external/{provider}/sign-in` | Begin an enabled OpenID Connect sign-in for non-browser clients that can send scope headers. |
| `GET` | `/external/{provider}/link` | Begin a provider link for non-browser clients that can send scope and bearer headers. |

The browser variants under `/api/auth/browser` keep refresh material in HttpOnly cookies. Scope-aware hosts also require `X-Tenant-Id`; protected endpoints require a bearer access token.

Registration remains backward-compatible: creating a password account does not suddenly require verified email. Products can request verification after registration and enforce `IsVerified` in their own onboarding/access policy. This avoids silently breaking existing applications while making verification state and delivery durable.

## OpenID Connect adapter

Compose the adapter explicitly after Auth:

```csharp
builder.AddAuthModule(AuthProfile.ScopeAware());
builder.AddAuthOpenIdConnectProviders();
```

The adapter uses confidential authorization-code flow with PKCE, HTTPS metadata, a short-lived secure temporary cookie, `SaveTokens = false`, and an allowlist for absolute return origins. Relative local return paths are allowed. The callback path is deterministic:

```text
/api/auth/external/callback/{provider-key}
```

For example, register these redirect URIs with the providers:

```text
https://api.example.com/api/auth/external/callback/google
https://api.example.com/api/auth/external/callback/microsoft
```

```json
{
  "Auth": {
    "OpenIdConnect": {
      "Enabled": true,
      "AllowedReturnUrls": [ "https://app.example.com/auth/complete" ],
      "Providers": {
        "google": {
          "Enabled": true,
          "Authority": "https://accounts.google.com",
          "ClientId": "from-secret-provider",
          "ClientSecret": "from-secret-provider",
          "Scopes": [ "openid", "email", "profile" ],
          "EmailClaim": "email",
          "EmailVerifiedClaim": "email_verified",
          "TreatEmailAsVerified": false
        },
        "microsoft": {
          "Enabled": true,
          "Authority": "https://login.microsoftonline.com/common/v2.0",
          "ClientId": "from-secret-provider",
          "ClientSecret": "from-secret-provider",
          "Scopes": [ "openid", "email", "profile" ],
          "EmailClaim": "email",
          "EmailVerifiedClaim": "email_verified",
          "TreatEmailAsVerified": false
        }
      }
    }
  }
}
```

`TreatEmailAsVerified` is an explicit trust decision for providers that do not emit a boolean verification claim. It is false in the Google and Microsoft examples so generated applications fail closed. Enable it only when the configured issuer guarantees ownership of the selected email claim. It still cannot merge into an existing account; explicit authenticated linking is required. Custom providers can select different email claim names without changing Auth.

Browser applications first post `{ "returnUrl": "..." }` to the sign-in or link challenge endpoint. The response contains a same-origin `startUrl`; navigate the top-level browser to that URL. GMA transfers the scope and, for links, authenticated member/session identity through a five-minute, HttpOnly, data-protected handoff cookie that the browser deletes when the challenge begins. This avoids putting access tokens, member ids, or protected handoff state in URLs and works with scope-aware applications whose tenant header cannot be attached to top-level navigation. The adapter exposes the same challenge contract with an empty provider list while disabled, so mounted-package OpenAPI remains stable.

The frontend receives `code` and `provider` on its allowlisted return URL, then posts the code once to `/external/exchange` or `/browser/external/exchange`. Do not log the code or place GMA access/refresh tokens in a redirect URL. Browser sign-in/link and callback load balancing require the same persisted Data Protection key ring across API replicas.

## Password and provider hybrid

External-only members can add a password from a fresh provider-authenticated session. Password members can link any number of configured providers. Existing passwords require the current password before change/removal. Unlinking the provider used by the current session requires an alternate proof; another linked provider or password must remain.

`GET /methods` is the self-service source for account-security UI. Admin member details additively expose password presence, verified-email presence, and linked provider names.

## Email verification and notifications

Auth generates a high-entropy verification code, stores only its rotating HMAC hash, and publishes `MemberEmailVerificationRequestedIntegrationEvent`. The raw code exists only in the transactional message path needed for delivery and expires according to `EmailVerificationLifetimeMinutes`. Requests have an account-level cooldown and the public paths are expected to remain edge-rate-limited.

The independent GMA Extensions repository owns the optional `Gma.Extensions.Auth.Notifications` bridge. It maps Auth events to mandatory tagged notifications without making Auth or Notifications depend on one another:

- sign-in: `delivery:web`, `delivery:email`, `domain:security`, `domain:authentication`;
- authentication-method change: web and email security alert;
- verification request: mandatory email delivery to the exact pending address;
- verification completed: mandatory web security notification.

Compose Auth, Notifications, the bridge, and an email transport explicitly:

```csharp
builder.AddModule<NotificationsModule>();
builder.Services.AddAuthNotificationsExtension();
builder.Services.AddNotificationEmailAdapter(builder.Configuration);
builder.Services.AddSingleton<IEmailSender, ProductEmailSender>();
```

The shared `Gma.Framework.Email` project contains transport-neutral message contracts only. Vendor credentials and SDKs belong in a product/provider adapter. If the extension or Notifications email adapter is absent, Auth still records verification state and publishes events, but no email is sent.

## Persistence and retention

Auth owns the `auth` schema and `auth.__ef_migrations_history`. SQL Server and PostgreSQL migrations include nullable password hashes, external identities, verification state, authentication methods on sessions, one-time exchange records, uniqueness constraints, and cleanup indexes.

Retention is opt-in and bounded through the shared `BoundedBatchProcessor`. It deletes old expired exchanges and sessions in configured batches across scopes. Active-session projections treat refresh-expired sessions as inactive even before cleanup.

```json
{
  "Auth": {
    "ExternalExchangeLifetimeMinutes": 5,
    "ExternalLinkSessionFreshnessMinutes": 10,
    "EmailVerificationLifetimeMinutes": 1440,
    "EmailVerificationRequestCooldownSeconds": 60,
    "Retention": {
      "Enabled": false,
      "ExpiredExchangeHistoryHours": 24,
      "SessionHistoryDays": 365,
      "BatchSize": 500,
      "MaxBatchesPerCategoryPerCycle": 4,
      "IntervalMinutes": 60
    }
  }
}
```

Run the selected provider migrations before enabling external identities. Keep database and message storage encrypted at rest because short-lived delivery payloads necessarily contain verification content until consumed/retained.

## Integration events

Auth publishes versioned, scope-aware events under `{application-namespace}.auth.*`:

- `member-registered.v1`;
- `member-disabled.v1`;
- `member-enabled.v1`;
- `member-sessions-revoked.v1`;
- `member-authenticated.v1`;
- `member-authentication-method-changed.v1`;
- `member-email-verification-requested.v1`;
- `member-email-verified.v1`.

Consumers bind explicitly to Auth as producer. Event ids are reused as notification ids, giving inbox processing and notification projection natural idempotency.

## Operational notes

- Use secret providers for JWT signing keys, refresh-token peppers, and OIDC client secrets.
- Persist and share the ASP.NET Core Data Protection key ring across replicas, with a stable application name, so OIDC state and correlation cookies survive restarts and callback load balancing.
- Auth has no secret default. A single-key deployment can inject `Auth__RefreshTokens__Pepper`; use the keyed pepper ring for rotation.
- Replace the in-process `IAuthenticationAttemptLimiter` in multi-replica deployments with a distributed implementation while retaining edge/IP rate limits.
- Replace the small built-in password blocklist with a current breach corpus/service for production products.
- Alert on failed Auth outbox/inbox processing and Notifications exhausted/unroutable delivery jobs.
- Keep provider callbacks and exchange/verification endpoints on the sensitive rate-limit policy.
- MFA, passkeys, account recovery, profile data, and KYC/KYB should be separate adapters/modules built on these identity and event seams, not embedded in the `Member` aggregate prematurely.
