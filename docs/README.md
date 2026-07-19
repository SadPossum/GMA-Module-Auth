# Auth Module

Implementation planning: [Global Identity With Ambient Tenancy](global-identity-with-tenancy-task.md), [Account Recovery](account-recovery-task.md), [Authentication Assurance And Step-Up](authentication-assurance-task.md), [TOTP Authenticator Lifecycle And Recovery](mfa-authenticator-lifecycle-task.md), and [Auth Production Hardening](auth-production-hardening-task.md).

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
Gma.Modules.Auth.Authenticators.Totp
Gma.Modules.Auth.Providers.OpenIdConnect
Gma.Modules.Auth.Admin.Contracts
Gma.Modules.Auth.AdminCli
Gma.Modules.Auth.AdminApi
```

The domain and application layers do not depend on ASP.NET Core authentication handlers or a vendor SDK. Provider adapters validate an upstream assertion and pass a normalized `ValidatedExternalIdentity` into Auth. Other modules consume Auth contracts or the narrow `IAuthMemberContactReader`; they do not query Auth tables.

Auth can be composed in two scope modes. `AuthProfile.ScopeAware()` follows the ambient scope and preserves tenant-isolated identity stores. `AuthProfile.Global("identity")` uses one fixed Auth-owned scope even when the host also has an active tenant context. The latter is appropriate for products where one public account can join multiple tenant-owned organizations; tenant membership and authorization remain outside Auth.

## Security invariants

- An external identity key is the exact `(scope, issuer, subject)` tuple. Email is never an external identity key. Persistence indexes a fixed SHA-256 key and still verifies issuer/subject exactly, avoiding oversized SQL Server keys while making the theoretical collision case fail closed.
- A provider email can create a new account only when it is provider-verified. A matching local email returns `link-required`; Auth never auto-merges accounts by email.
- Password and external self-registration are independently configurable and default to enabled for backward compatibility. Disabled registration fails closed in the application handlers; hiding a client control is never the security boundary.
- Linking is bound to the exact authenticated member and session that initiated it, and that session must be fresh.
- A member can link multiple providers. Removing a password or external identity cannot leave the member with no authentication method.
- Provider access/refresh tokens are not stored. The browser callback receives only a short-lived, hashed, single-use GMA exchange code.
- Passwords and verification codes are stored only as hashes. Refresh-token hashing supports active and previous peppers for rotation.
- Refresh-token replay revokes active sessions. Admin password reset also revokes active sessions.
- Password recovery is enumeration-safe, accepts only active password members with a verified email, stores only a rotating HMAC code hash, and revokes every session after confirmation.
- An active local TOTP authenticator is enforced after every password and external primary sign-in. Auth issues no session or token until the one-time primary challenge succeeds.
- TOTP secrets are protected at rest, accepted time steps cannot replay, recovery codes are stored only as keyed hashes, and invalid challenge or management attempts are retained durably for bounded rate limiting.
- Sign-ins and authentication-method changes publish security events with bounded client context; secrets and provider tokens are excluded.
- Scope context and the access-token scope claim must agree on protected scope-aware endpoints.
- Scope-aware OIDC challenges carry the normalized scope only inside protected authentication state and restore it before the callback transaction; provider redirects do not depend on tenant headers surviving the round trip.

## User API

Base path: `/api/auth`.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/self-registration` | Discover whether password and external self-registration are enabled for the active scope. |
| `POST` | `/register` | Create a password account. |
| `POST` | `/login` | Authenticate with username/password. |
| `POST` | `/refresh` | Rotate a refresh token. |
| `POST` | `/step-up/password` | Reauthenticate the current session with its password and rotate the refresh token. |
| `POST` | `/sign-out` | Revoke one session. |
| `POST` | `/sign-out-all` | Revoke all sessions. |
| `GET` | `/methods` | List password, email verification, and linked-provider state. |
| `PUT` | `/password` | Add or change a password after fresh authentication. |
| `POST` | `/password/remove` | Remove a password when another method remains. |
| `POST` | `/password-recovery` | Request an enumeration-safe password recovery email. |
| `POST` | `/password-recovery/confirm` | Consume a one-time recovery code, replace the password, and revoke all sessions. |
| `POST` | `/external-identities/{id}/unlink` | Unlink a provider without account lockout. |
| `POST` | `/email-verification` | Request a bounded, cooldown-protected verification challenge. |
| `POST` | `/email-verification/confirm` | Confirm a one-time verification code. |
| `POST` | `/external/exchange` | Exchange a provider callback code for GMA tokens or complete a link. |
| `GET` | `/external/providers` | Discover enabled OpenID Connect provider codes. |
| `POST` | `/external/{provider}/sign-in/challenge` | Create a browser-safe sign-in challenge handoff. |
| `POST` | `/external/{provider}/link/challenge` | Create an authenticated browser-safe link challenge handoff. |
| `GET` | `/external/{provider}/sign-in` | Begin an enabled OpenID Connect sign-in for non-browser clients that can send scope headers. |
| `GET` | `/external/{provider}/link` | Begin a provider link for non-browser clients that can send scope and bearer headers. |
| `GET` | `/mfa` | Read provider availability, enrollment state, activation time, and unused recovery-code count. |
| `POST` | `/mfa/totp/enrollment` | Begin or replace an expired pending TOTP enrollment from a fresh session. |
| `POST` | `/mfa/totp/activate` | Verify enrollment, rotate the session, and return recovery codes once. |
| `POST` | `/mfa/challenges/complete` | Complete a password or external primary challenge with TOTP or a recovery code. |
| `POST` | `/mfa/recovery-codes/regenerate` | Replace recovery codes after factor and refresh proof. |
| `POST` | `/mfa/totp/disable` | Disable TOTP after factor and refresh proof, then revoke all sessions. |

The browser variants under `/api/auth/browser` keep refresh material in HttpOnly cookies. Scope-aware hosts also require `X-Tenant-Id`; protected endpoints require a bearer access token.

Registration remains backward-compatible: creating a password account does not suddenly require verified email. Products can request verification after registration and enforce `IsVerified` in their own onboarding/access policy. This avoids silently breaking existing applications while making verification state and delivery durable.

Products that provision accounts through an administrator or invitation workflow should disable both public account-creation paths. Existing password/provider sign-in, explicit provider linking, and admin member creation remain available:

```json
{
  "Auth": {
    "SelfRegistration": {
      "PasswordEnabled": false,
      "ExternalEnabled": false
    }
  }
}
```

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

## Authentication assurance and step-up

Auth persists the authentication context (`acr`), method references (`amr`), and authentication-event time (`auth_time`) that established each session's current evidence. Password sign-in emits the standard `pwd` method reference. External sign-in uses a conservative external context and does not claim an upstream method that the configured adapter has not validated.

An ordinary refresh rotates refresh material but preserves the authentication event. It cannot make a session stronger or fresher. Password step-up verifies the authenticated member, exact active session, current password, scope, rate limit, and refresh token; then it rotates the refresh token, records a distinct reauthentication event, and issues an access token from the persisted evidence. Reuse of the pre-step-up refresh token triggers the existing all-session replay response.

Bearer clients call `POST /api/auth/step-up/password` with the password and refresh token. Browser clients call `POST /api/auth/browser/step-up/password` with the password while the HttpOnly refresh cookie remains on the browser-auth path. Both return replacement access and refresh material through their existing transport conventions.

Products decide which operations require accepted contexts and/or recent authentication. The dependency-neutral `Gma.Framework.Security` package owns the requirement and claim vocabulary; the optional `Gma.Framework.Security.AspNetCore` adapter emits RFC 9470 `insufficient_user_authentication` challenges. Auth does not rank methods or claim that a method name alone satisfies a NIST assurance level.

## TOTP authenticator adapter

TOTP lifecycle and enforcement belong to Auth, while the RFC 6238 implementation is an explicit optional adapter:

```csharp
builder.AddAuthModule(AuthProfile.ScopeAware());
builder.AddAuthTotpAuthenticator();
```

The adapter uses Otp.NET with a random 160-bit secret, SHA-1, six digits, a 30-second period, and the current or immediately previous time step. Auth persists the matched step and rejects replay. Password plus TOTP/recovery uses `urn:gma:acr:mfa`; external plus a local factor uses the conservative `urn:gma:acr:two-step` context because Auth does not invent upstream provider factor evidence.

`AddAuthTotpAuthenticator` replaces Auth's fail-closed unavailable ports. A host that uses KMS/HSM secret custody or another validated TOTP implementation registers its replacement ports after the adapter. The default protector uses ASP.NET Core Data Protection. Production hosts must give it a stable application name and a persisted, encrypted, replica-shared key ring. Losing that key ring makes existing TOTP secrets unusable; an ephemeral key ring is not a production configuration.

Enrollment and recovery-code responses are one-time secret-bearing responses and use `Cache-Control: no-store`. Browser routes keep refresh tokens in the existing HttpOnly cookie transport. Administrative recovery is a confirmed `reset-multi-factor` operation with a dedicated scoped permission, bounded reason, Auth security event, challenge invalidation, and all-session revocation.

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

## Password recovery

Account recovery is an Auth-owned capability because changing a credential and revoking sessions must remain one Auth transaction. Its challenge is a separate scoped aggregate and table; recovery state is not added to `Member`.

`POST /password-recovery` accepts an email address and returns `202 Accepted` for every structurally valid request. Auth publishes a delivery event only when the active scope contains an active password member with that exact active verified email. Unknown, disabled, unverified, and external-only accounts receive the same public response. A durable account cooldown suppresses repeated challenge creation; hosts must additionally apply sensitive endpoint and IP rate limits.

`POST /password-recovery/confirm` accepts the high-entropy one-time code and a new password. The code is looked up only through candidate HMAC hashes in the active Auth scope. Successful confirmation atomically consumes the challenge, invalidates other active challenges, applies the normal password policy, changes the password, revokes all sessions, and publishes the existing security events. It does not issue tokens or sign the member in.

`Gma.Extensions.Auth.Notifications` optionally maps the requested event to mandatory email-only delivery at the exact verified address carried by Auth. The event includes a challenge id for product-specific link templates and audit correlation, but the generic confirmation contract needs only the code. Recovery secrets are never projected to web notifications. Hosts must encrypt and tightly retain every Auth, messaging, Notifications, and email-delivery record that temporarily carries the code.

## Persistence and retention

Auth owns the `auth` schema and `auth.__ef_migrations_history`. SQL Server and PostgreSQL migrations include nullable password hashes, external identities, verification state, authentication methods and assurance evidence on sessions, one-time exchange and recovery records, uniqueness constraints, and cleanup indexes.

Retention is opt-in and bounded through the shared `BoundedBatchProcessor`. It deletes old expired exchanges and sessions in configured batches across scopes. Active-session projections treat refresh-expired sessions as inactive even before cleanup.

```json
{
  "Auth": {
    "ExternalExchangeLifetimeMinutes": 5,
    "ExternalLinkSessionFreshnessMinutes": 10,
    "EmailVerificationLifetimeMinutes": 1440,
    "EmailVerificationRequestCooldownSeconds": 60,
    "PasswordRecoveryLifetimeMinutes": 30,
    "PasswordRecoveryRequestCooldownSeconds": 60,
    "Retention": {
      "Enabled": false,
      "ExpiredExchangeHistoryHours": 24,
      "PasswordRecoveryHistoryHours": 24,
      "SessionHistoryDays": 365,
      "AuthenticationChallengeHistoryHours": 24,
      "ExpiredTotpEnrollmentHistoryHours": 24,
      "DisabledTotpAuthenticatorHistoryDays": 365,
      "MultiFactorFailureHistoryHours": 24,
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
- `member-password-recovery-requested.v1`;
- `member-email-verification-requested.v1`;
- `member-email-verified.v1`.
- `member-multi-factor-authentication-reset.v1`.

Consumers bind explicitly to Auth as producer. Event ids are reused as notification ids, giving inbox processing and notification projection natural idempotency.

## Operational notes

- Use secret providers for JWT signing keys, refresh-token peppers, and OIDC client secrets.
- Persist and share the ASP.NET Core Data Protection key ring across replicas, with a stable application name, so OIDC state and correlation cookies survive restarts and callback load balancing.
- Encrypt and persist that same key ring before enabling the default TOTP protector; test key restoration and rotation as part of deployment recovery drills.
- Auth has no secret default. A single-key deployment can inject `Auth__RefreshTokens__Pepper`; use the keyed pepper ring for rotation.
- Replace the in-process `IAuthenticationAttemptLimiter` in multi-replica deployments with a distributed implementation while retaining edge/IP rate limits.
- Replace the small built-in password blocklist with a current breach corpus/service for production products.
- Alert on failed Auth outbox/inbox processing and Notifications exhausted/unroutable delivery jobs.
- Keep provider callbacks and exchange/verification endpoints on the sensitive rate-limit policy.
- Passkeys and additional authenticator types should extend the authentication-evidence foundation through explicit adapters and Auth-owned lifecycle state. Profile data and KYC/KYB remain separate product capabilities and do not belong in the `Member` aggregate.
