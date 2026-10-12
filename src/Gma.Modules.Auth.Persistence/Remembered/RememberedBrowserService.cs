namespace Gma.Modules.Auth.Persistence.Remembered;

using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using MemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

internal sealed partial class RememberedBrowserService(
    AuthDbContext db,
    RememberedBrowserRequestContext request,
    IAuthScopeContext scope,
    IOptions<RememberedBrowserOptions> options,
    IOptions<AuthApplicationOptions> authOptions,
    IMemberRepository members,
    RememberedPinHasher pins,
    IAuthenticationAttemptLimiter attempts,
    ITokenService tokens,
    IRefreshTokenHashingService refreshHashes,
    ISystemClock clock,
    IRememberedBrowserAccountProfileReader profiles) : IRememberedBrowserService
{
    private RememberedBrowserDevice? device;

    public async Task<RememberedBrowserCurrentResponse> CurrentAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled)
        {
            return this.Empty(RememberedBrowserState.Unavailable);
        }

        this.device = await this.FindDeviceAsync(cancellationToken).ConfigureAwait(false);
        return await this.ProjectAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RememberedBrowserOperationResponse> OutcomeAsync(Guid operationId, CancellationToken cancellationToken)
    {
        this.device = await this.FindDeviceAsync(cancellationToken).ConfigureAwait(false);
        if (!this.DeviceIsValid())
        {
            return new(RememberedBrowserOutcome.AuthenticationRequired, await this.ProjectAsync(cancellationToken).ConfigureAwait(false));
        }

        RememberedBrowserOperationReceipt? receipt = await db.RememberedBrowserOperations
            .AsNoTracking()
            .SingleOrDefaultAsync(value => value.DeviceId == this.device!.Id && value.OperationId == operationId, cancellationToken)
            .ConfigureAwait(false);
        RememberedBrowserOutcome outcome = receipt is null
            ? RememberedBrowserOutcome.NotFound
            : receipt.ResultGeneration == this.device!.Generation
                ? receipt.Outcome
                : RememberedBrowserOutcome.StateChanged;
        return new(outcome, await this.ProjectAsync(cancellationToken).ConfigureAwait(false));
    }

    public async Task<RememberedBrowserCompletion> ExecuteAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled)
        {
            return new(new(RememberedBrowserOutcome.Unavailable, this.Empty(RememberedBrowserState.Unavailable)));
        }

        if (operation.Kind == RememberedBrowserOperationKind.Device)
        {
            return await this.BootstrapAsync(operation, cancellationToken).ConfigureAwait(false);
        }

        if (!this.DeviceIsValid())
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        if (operation.Kind == RememberedBrowserOperationKind.Activity)
        {
            return await this.ActivityAsync(operation, cancellationToken).ConfigureAwait(false);
        }

        if (operation.OperationId == Guid.Empty || operation.ExpectedGeneration <= 0)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        RememberedBrowserOperationReceipt? receipt = await db.RememberedBrowserOperations
            .SingleOrDefaultAsync(value => value.DeviceId == this.device!.Id && value.OperationId == operation.OperationId, cancellationToken)
            .ConfigureAwait(false);
        if (receipt is not null)
        {
            return await this.ReplayAsync(operation, receipt, cancellationToken).ConfigureAwait(false);
        }

        if (operation.Kind == RememberedBrowserOperationKind.Recover)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.NotFound, cancellationToken).ConfigureAwait(false);
        }

        if (operation.ExpectedGeneration != this.device!.Generation)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        RememberedBrowserCompletion result = operation.Kind switch
        {
            RememberedBrowserOperationKind.Remember => await this.RememberAsync(operation, cancellationToken).ConfigureAwait(false),
            RememberedBrowserOperationKind.Select => await this.SelectAsync(operation, cancellationToken).ConfigureAwait(false),
            RememberedBrowserOperationKind.Lock or RememberedBrowserOperationKind.BeginSignIn or
                RememberedBrowserOperationKind.CancelSignIn or RememberedBrowserOperationKind.Forget or
                RememberedBrowserOperationKind.ForgetDevice => await this.TransitionAsync(operation, cancellationToken).ConfigureAwait(false),
            _ => await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false)
        };
        if (result.Response.Outcome == RememberedBrowserOutcome.Applied)
        {
            db.RememberedBrowserOperations.Add(new()
            {
                DeviceId = this.device.Id,
                OperationId = operation.OperationId,
                ScopeId = this.device.ScopeId,
                Kind = operation.Kind,
                ExpectedGeneration = operation.ExpectedGeneration,
                ResultGeneration = this.device.Generation,
                ProofId = operation.Kind == RememberedBrowserOperationKind.Forget ? operation.ProofId : this.device.ActiveProofId,
                MemberId = this.device.ActiveMemberId,
                SessionId = this.device.ActiveSessionId,
                Outcome = RememberedBrowserOutcome.Applied,
                CreatedAtUtc = clock.UtcNow
            });
        }

        return result;
    }

    private async Task<RememberedBrowserCompletion> BootstrapAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        if (this.device is not null)
        {
            return await this.CompleteAsync(this.DeviceIsValid()
                ? RememberedBrowserOutcome.Applied : RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        Member? member = await this.FindMemberAsync(operation.MemberId, cancellationToken).ConfigureAwait(false);
        MemberSession? session = member?.Sessions.SingleOrDefault(value => value.Id.Value == operation.SessionId);
        if (member is null || session is null || !await this.StrongSessionAsync(member, session, cancellationToken).ConfigureAwait(false) ||
            session.RememberedBrowserDeviceId is not null || string.IsNullOrEmpty(scope.ScopeId))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        string credential = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        this.device = new()
        {
            Id = Guid.CreateVersion7(),
            ScopeId = member.ScopeId,
            CredentialHash = HashCredential(credential),
            RestoreEpoch = options.Value.RestoreEpoch,
            PinDigits = options.Value.PinDigits,
            State = RememberedBrowserState.Active,
            ActiveMemberId = member.Id.Value,
            ActiveSessionId = session.Id.Value,
            CreatedAtUtc = clock.UtcNow,
            ExpiresAtUtc = session.AbsoluteExpiresAtUtc,
            IdleExpiresAtUtc = Min(clock.UtcNow.AddMinutes(options.Value.IdleMinutes), session.AbsoluteExpiresAtUtc)
        };
        db.RememberedBrowserDevices.Add(this.device);
        return new(new(RememberedBrowserOutcome.Applied, await this.ProjectAsync(cancellationToken).ConfigureAwait(false)),
            DeviceCredential: credential, CookieExpiresAtUtc: this.device.ExpiresAtUtc);
    }

    private async Task<RememberedBrowserCompletion> RememberAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        Member? member = await this.FindMemberAsync(operation.MemberId, cancellationToken).ConfigureAwait(false);
        MemberSession? original = member?.Sessions.SingleOrDefault(value => value.Id.Value == operation.SessionId);
        string? label = string.IsNullOrWhiteSpace(operation.Label) ? null : operation.Label.Trim().Normalize(NormalizationForm.FormC);
        if (!operation.Consent || member is null || original is null || !await this.StrongSessionAsync(member, original, cancellationToken).ConfigureAwait(false) ||
            this.device!.ActiveMemberId != member.Id.Value || this.device.ActiveSessionId != original.Id.Value ||
            !await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false) ||
            !RememberedPinHasher.IsValid(operation.Pin, this.device.PinDigits) ||
            (label is not null && (label.Length > MemberUsername.ValueMaxLength || label.Any(char.IsControl))))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        RememberedAccountProof? proof = await db.RememberedAccountProofs.SingleOrDefaultAsync(
            value => value.DeviceId == this.device.Id && value.MemberId == member.Id.Value, cancellationToken).ConfigureAwait(false);
        if (proof is null && await db.RememberedAccountProofs.CountAsync(
            value => value.DeviceId == this.device.Id && value.RevokedAtUtc == null, cancellationToken).ConfigureAwait(false) >= options.Value.MaximumAccounts)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.SessionLimitReached, cancellationToken).ConfigureAwait(false);
        }

        proof ??= new() { Id = Guid.CreateVersion7(), ScopeId = member.ScopeId, DeviceId = this.device.Id, MemberId = member.Id.Value };
        if (db.Entry(proof).State == EntityState.Detached)
        {
            db.RememberedAccountProofs.Add(proof);
        }

        proof.OriginalSessionId = original.Id.Value;
        proof.SecurityEpoch = member.SecurityEpoch;
        proof.PinHash = await pins.HashAsync(this.device.Id, proof.Id, operation.Pin!, cancellationToken).ConfigureAwait(false);
        if (!await this.StrongSessionAsync(member, original, cancellationToken).ConfigureAwait(false) ||
            !await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new RememberedBrowserStateChangedException();
        }

        proof.PepperVersion = options.Value.PepperVersion;
        proof.Label = label;
        proof.CreatedAtUtc = clock.UtcNow;
        proof.AuthenticatedAtUtc = original.AuthenticatedAtUtc;
        proof.ExpiresAtUtc = Min(original.AbsoluteExpiresAtUtc, this.device.ExpiresAtUtc);
        proof.RevokedAtUtc = null;
        SessionAuthenticationEvidence evidence = new(original.AuthenticationContextReference,
            original.AuthenticationMethodReferences, original.AuthenticatedAtUtc);
        string authenticationMethod = original.AuthenticationMethod;
        await this.CloseActiveAsync(cancellationToken).ConfigureAwait(false);
        return await this.IssueAsync(member, proof, authenticationMethod, evidence, cancellationToken).ConfigureAwait(false);
    }

    private async Task<RememberedBrowserCompletion> SelectAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        if (operation.ProofId is not { } proofId || proofId == Guid.Empty)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        RememberedAccountProof? proof = await db.RememberedAccountProofs.SingleOrDefaultAsync(
            value => value.Id == proofId && value.DeviceId == this.device!.Id, cancellationToken).ConfigureAwait(false);
        Member? member = await this.FindMemberAsync(proof?.MemberId, cancellationToken).ConfigureAwait(false);
        if (proof is null || member is null || !this.ProofIsValid(proof, member))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        RememberedBrowserOutcome pin = await this.VerifyPinAsync(proof, operation.Pin, cancellationToken).ConfigureAwait(false);
        if (pin != RememberedBrowserOutcome.Applied)
        {
            return await this.CompleteAsync(pin, cancellationToken).ConfigureAwait(false);
        }

        int otherSessions = member.Sessions.Count(value => value.IsActive && value.RefreshTokenExpiresAtUtc > clock.UtcNow &&
            value.AbsoluteExpiresAtUtc > clock.UtcNow && value.Id.Value != this.device!.ActiveSessionId);
        if (otherSessions >= authOptions.Value.MaximumActiveSessionsPerMember)
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.SessionLimitReached, cancellationToken).ConfigureAwait(false);
        }

        await this.CloseActiveAsync(cancellationToken).ConfigureAwait(false);
        return await this.IssueAsync(member, proof, MemberAuthenticationMethods.DevicePin,
            new(AuthenticationContextReferences.DevicePin, [AuthenticationMethodReferences.DevicePin], proof.AuthenticatedAtUtc),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<RememberedBrowserCompletion> IssueAsync(
        Member member,
        RememberedAccountProof proof,
        string authenticationMethod,
        SessionAuthenticationEvidence evidence,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;
        string refresh = tokens.GenerateRefreshToken();
        Result<MemberSession> created = member.StartSession(new(Guid.CreateVersion7()), refreshHashes.HashRefreshToken(refresh),
            Min(now.AddDays(authOptions.Value.RefreshTokenLifetimeDays), proof.ExpiresAtUtc), now,
            authenticationMethod, evidence, int.MaxValue, proof.ExpiresAtUtc);
        if (created.IsFailure)
        {
            throw new RememberedBrowserStateChangedException();
        }

        MemberSession child = created.Value;
        this.Activate(member, child, proof.Id);
        _ = member.RecordAuthentication(child.Id, Guid.CreateVersion7(), now);
        string access = this.AccessToken(member, child);
        return new(new(RememberedBrowserOutcome.Applied, await this.ProjectAsync(cancellationToken).ConfigureAwait(false), access),
            refresh, CookieExpiresAtUtc: child.RefreshTokenExpiresAtUtc);
    }

    private async Task<RememberedBrowserCompletion> ReplayAsync(
        RememberedBrowserOperation operation,
        RememberedBrowserOperationReceipt receipt,
        CancellationToken cancellationToken)
    {
        bool recovery = operation.Kind == RememberedBrowserOperationKind.Recover;
        if (receipt.ExpectedGeneration != operation.ExpectedGeneration || receipt.ResultGeneration != this.device!.Generation ||
            (!recovery && (operation.Kind != receipt.Kind ||
                ((operation.Kind is RememberedBrowserOperationKind.Select or RememberedBrowserOperationKind.Forget) &&
                operation.ProofId != receipt.ProofId))))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        if (receipt.Kind is not (RememberedBrowserOperationKind.Remember or RememberedBrowserOperationKind.Select))
        {
            return await this.CompleteAsync(recovery ? RememberedBrowserOutcome.StateChanged : receipt.Outcome, cancellationToken).ConfigureAwait(false);
        }

        if (receipt.ProofId is null || receipt.SessionId != this.device.ActiveSessionId ||
            receipt.ProofId != this.device.ActiveProofId || receipt.MemberId != this.device.ActiveMemberId ||
            !await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        RememberedAccountProof? proof = await db.RememberedAccountProofs.SingleOrDefaultAsync(
            value => value.Id == receipt.ProofId && value.DeviceId == this.device.Id, cancellationToken).ConfigureAwait(false);
        Member? member = await this.FindMemberAsync(receipt.MemberId, cancellationToken).ConfigureAwait(false);
        MemberSession? session = member?.Sessions.SingleOrDefault(value => value.Id.Value == receipt.SessionId);
        if (proof is null || member is null || session is null || !this.ProofIsValid(proof, member))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.AuthenticationRequired, cancellationToken).ConfigureAwait(false);
        }

        RememberedBrowserOutcome pin = await this.VerifyPinAsync(proof, operation.Pin, cancellationToken).ConfigureAwait(false);
        if (pin != RememberedBrowserOutcome.Applied)
        {
            return await this.CompleteAsync(pin, cancellationToken).ConfigureAwait(false);
        }

        string refresh = tokens.GenerateRefreshToken();
        Result<MemberSession> reissued = member.ReissueRememberedCredentials(session.Id, refreshHashes.HashRefreshToken(refresh),
            Min(clock.UtcNow.AddDays(authOptions.Value.RefreshTokenLifetimeDays), proof.ExpiresAtUtc), clock.UtcNow);
        if (reissued.IsFailure)
        {
            throw new RememberedBrowserStateChangedException();
        }

        this.device.Touch();
        return new(new(RememberedBrowserOutcome.Applied, await this.ProjectAsync(cancellationToken).ConfigureAwait(false),
            this.AccessToken(member, session)), refresh, CookieExpiresAtUtc: session.RefreshTokenExpiresAtUtc);
    }

    private async Task<RememberedBrowserCompletion> TransitionAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        if (operation.Kind == RememberedBrowserOperationKind.CancelSignIn &&
            this.device!.State != RememberedBrowserState.SigningIn &&
            !(this.device.State == RememberedBrowserState.Active && this.device.ActiveProofId is null))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        if (operation.Kind == RememberedBrowserOperationKind.Forget)
        {
            RememberedAccountProof? proof = await db.RememberedAccountProofs.SingleOrDefaultAsync(
                value => value.Id == operation.ProofId && value.DeviceId == this.device!.Id, cancellationToken).ConfigureAwait(false);
            if (proof is null || operation.ProofId == Guid.Empty)
            {
                return await this.CompleteAsync(RememberedBrowserOutcome.NotFound, cancellationToken).ConfigureAwait(false);
            }

            proof.RevokedAtUtc ??= clock.UtcNow;
            // Changing the chooser is a device transition; every active child is fenced.
        }

        await this.CloseActiveAsync(cancellationToken).ConfigureAwait(false);
        this.device!.Generation = checked(this.device.Generation + 1);
        this.device.State = operation.Kind == RememberedBrowserOperationKind.BeginSignIn
            ? RememberedBrowserState.SigningIn
            : RememberedBrowserState.Locked;
        if (operation.Kind == RememberedBrowserOperationKind.ForgetDevice)
        {
            this.device.State = RememberedBrowserState.Revoked;
            this.device.RevokedAtUtc = clock.UtcNow;
            RememberedAccountProof[] proofs = await db.RememberedAccountProofs
                .Where(value => value.DeviceId == this.device.Id && value.RevokedAtUtc == null)
                .ToArrayAsync(cancellationToken).ConfigureAwait(false);
            foreach (RememberedAccountProof proof in proofs)
            {
                proof.RevokedAtUtc = clock.UtcNow;
            }
        }

        this.device.Touch();
        return await this.CompleteAsync(RememberedBrowserOutcome.Applied, cancellationToken).ConfigureAwait(false);
    }

    private async Task<RememberedBrowserCompletion> ActivityAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken)
    {
        if (operation.ExpectedGeneration != this.device!.Generation || operation.SessionId != this.device.ActiveSessionId ||
            operation.MemberId != this.device.ActiveMemberId || !await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false))
        {
            return await this.CompleteAsync(RememberedBrowserOutcome.StateChanged, cancellationToken).ConfigureAwait(false);
        }

        this.device.IdleExpiresAtUtc = Min(clock.UtcNow.AddMinutes(options.Value.IdleMinutes), this.device.ExpiresAtUtc);
        this.device.Touch();
        return await this.CompleteAsync(RememberedBrowserOutcome.Applied, cancellationToken).ConfigureAwait(false);
    }

    private async Task<RememberedBrowserOutcome> VerifyPinAsync(RememberedAccountProof proof, string? pin, CancellationToken cancellationToken)
    {
        if (!RememberedPinHasher.IsValid(pin, this.device!.PinDigits))
        {
            return RememberedBrowserOutcome.PinRejected;
        }

        AuthenticationAttemptPolicy devicePolicy = new(options.Value.DeviceAttemptLimit, TimeSpan.FromMinutes(options.Value.AttemptWindowMinutes));
        AuthenticationAttemptPolicy proofPolicy = new(options.Value.FailedPinLimit, TimeSpan.FromMinutes(options.Value.AttemptWindowMinutes));
        AuthenticationAttemptLease? deviceLease = await attempts.TryAcquireAsync(this.device.ScopeId, "remembered-device-pin",
            this.device.Id.ToString("N"), clock.UtcNow, devicePolicy, cancellationToken).ConfigureAwait(false);
        AuthenticationAttemptLease? proofLease = deviceLease is null ? null : await attempts.TryAcquireAsync(
            this.device.ScopeId, "remembered-account-pin", proof.Id.ToString("N"), clock.UtcNow, proofPolicy, cancellationToken).ConfigureAwait(false);
        if (deviceLease is null || proofLease is null)
        {
            return RememberedBrowserOutcome.RateLimited;
        }

        if (!await pins.VerifyAsync(proof, pin!, cancellationToken).ConfigureAwait(false))
        {
            return RememberedBrowserOutcome.PinRejected;
        }

        await attempts.RecordSuccessAsync(this.device.ScopeId, "remembered-account-pin", proof.Id.ToString("N"),
            proofLease.Value, cancellationToken).ConfigureAwait(false);
        return RememberedBrowserOutcome.Applied;
    }

    private async Task<bool> StrongSessionAsync(Member member, MemberSession session, CancellationToken cancellationToken)
    {
        bool primary = session.AuthenticationMethodReferences.Contains(AuthenticationMethodReferences.Password, StringComparer.Ordinal) ||
            session.AuthenticationMethodReferences.Contains(AuthenticationMethodReferences.External, StringComparer.Ordinal);
        if (member.Status != MemberStatus.Active || !session.IsActive || session.RefreshTokenExpiresAtUtc <= clock.UtcNow ||
            session.AbsoluteExpiresAtUtc <= clock.UtcNow || session.AuthenticatedAtUtc > clock.UtcNow ||
            session.AuthenticatedAtUtc < clock.UtcNow.AddMinutes(-authOptions.Value.ExternalLinkSessionFreshnessMinutes) ||
            session.AuthenticationMethod == MemberAuthenticationMethods.DevicePin || !primary ||
            session.AuthenticationContextReference is not (AuthenticationContextReferences.Password or
                AuthenticationContextReferences.External or AuthenticationContextReferences.MultiFactor or AuthenticationContextReferences.TwoStep))
        {
            return false;
        }

        bool configuredMfa = await db.MemberTotpAuthenticators.AnyAsync(
            value => value.MemberId == member.Id && value.ActivatedAtUtc != null && value.DisabledAtUtc == null,
            cancellationToken).ConfigureAwait(false);
        return !configuredMfa ||
            ((session.AuthenticationContextReference is AuthenticationContextReferences.MultiFactor or AuthenticationContextReferences.TwoStep) &&
            (session.AuthenticationMethodReferences.Contains(AuthenticationMethodReferences.OneTimePassword, StringComparer.Ordinal) ||
                session.AuthenticationMethodReferences.Contains(AuthenticationMethodReferences.RecoveryCode, StringComparer.Ordinal)));
    }

    private bool DeviceIsValid() => options.Value.Enabled && this.device is not null &&
        this.device.RevokedAtUtc is null && this.device.ExpiresAtUtc > clock.UtcNow &&
        this.device.RestoreEpoch == options.Value.RestoreEpoch && this.device.ScopeId == scope.ScopeId;

    private bool ProofIsValid(RememberedAccountProof proof, Member member) =>
        this.DeviceIsValid() && proof.DeviceId == this.device!.Id && proof.ScopeId == this.device.ScopeId &&
        proof.MemberId == member.Id.Value && proof.SecurityEpoch == member.SecurityEpoch &&
        member.Status == MemberStatus.Active && proof.RevokedAtUtc is null && proof.ExpiresAtUtc > clock.UtcNow &&
        proof.PepperVersion == options.Value.PepperVersion;

    private async Task<Member?> FindMemberAsync(Guid? memberId, CancellationToken cancellationToken) =>
        memberId is null || memberId == Guid.Empty ? null :
            db.Members.Local.FirstOrDefault(value => value.Id.Value == memberId && value.ScopeId == scope.ScopeId) ??
                await members.GetByIdAsync(new(memberId.Value), cancellationToken).ConfigureAwait(false);

    private async Task<RememberedBrowserDevice?> FindDeviceAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled || request.DeviceCredential is not { Length: 64 } credential ||
            !credential.All(char.IsAsciiHexDigit) || string.IsNullOrEmpty(scope.ScopeId))
        {
            return null;
        }

        string digest = HashCredential(credential);
        return await db.RememberedBrowserDevices.SingleOrDefaultAsync(
            value => value.CredentialHash == digest && value.ScopeId == scope.ScopeId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> ActiveIsValidAsync(CancellationToken cancellationToken)
    {
        if (!this.DeviceIsValid() || this.device!.State != RememberedBrowserState.Active ||
            this.device.IdleExpiresAtUtc <= clock.UtcNow || this.device.IdleExpiresAtUtc is null)
        {
            return false;
        }

        Member? member = await this.FindMemberAsync(this.device.ActiveMemberId, cancellationToken).ConfigureAwait(false);
        MemberSession? session = member?.Sessions.SingleOrDefault(value => value.Id.Value == this.device.ActiveSessionId);
        if (member is null || member.Status != MemberStatus.Active || session is null || !session.IsActive ||
            session.AbsoluteExpiresAtUtc <= clock.UtcNow || session.RefreshTokenExpiresAtUtc <= clock.UtcNow ||
            (session.RememberedBrowserDeviceId is not null &&
            (session.RememberedBrowserDeviceId != this.device.Id || session.RememberedBrowserGeneration != this.device.Generation ||
                session.RememberedSecurityEpoch != member.SecurityEpoch)))
        {
            return false;
        }

        if (this.device.ActiveProofId is not { } proofId)
        {
            return true;
        }

        RememberedAccountProof? proof = await db.RememberedAccountProofs.SingleOrDefaultAsync(
            value => value.Id == proofId && value.DeviceId == this.device.Id, cancellationToken).ConfigureAwait(false);
        proof ??= db.RememberedAccountProofs.Local.SingleOrDefault(
            value => value.Id == proofId && value.DeviceId == this.device.Id);
        return proof is not null && this.ProofIsValid(proof, member);
    }

    private async Task CloseActiveAsync(CancellationToken cancellationToken)
    {
        Member? member = await this.FindMemberAsync(this.device!.ActiveMemberId, cancellationToken).ConfigureAwait(false);
        if (member is not null && this.device.ActiveSessionId is { } sid)
        {
            _ = member.SignOutSession(new(sid), clock.UtcNow);
        }

        this.device.ActiveMemberId = null;
        this.device.ActiveSessionId = null;
        this.device.ActiveProofId = null;
        this.device.IdleExpiresAtUtc = null;
        this.device.Touch();
    }

    private void Activate(Member member, MemberSession session, Guid? proofId)
    {
        this.device!.Generation = checked(this.device.Generation + 1);
        this.device.State = RememberedBrowserState.Active;
        this.device.ActiveMemberId = member.Id.Value;
        this.device.ActiveSessionId = session.Id.Value;
        this.device.ActiveProofId = proofId;
        this.device.IdleExpiresAtUtc = Min(clock.UtcNow.AddMinutes(options.Value.IdleMinutes), session.AbsoluteExpiresAtUtc);
        session.BindRememberedBrowser(this.device.Id, proofId, this.device.Generation, member.SecurityEpoch);
        this.device.Touch();
    }

    private string AccessToken(Member member, MemberSession session) => tokens.GenerateAccessToken(new(
        member.Id, member.ScopeId, session.Id, new(session.AuthenticationContextReference,
            session.AuthenticationMethodReferences, session.AuthenticatedAtUtc)));

    private async Task<RememberedBrowserCompletion> CompleteAsync(RememberedBrowserOutcome outcome, CancellationToken cancellationToken) =>
        new(new(outcome, await this.ProjectAsync(cancellationToken).ConfigureAwait(false)));

    private async Task<RememberedBrowserCurrentResponse> ProjectAsync(CancellationToken cancellationToken)
    {
        if (this.device is null)
        {
            return this.Empty(RememberedBrowserState.Missing);
        }

        if (!this.DeviceIsValid())
        {
            return this.Empty(RememberedBrowserState.Revoked);
        }

        RememberedAccountProof[] proofs = await db.RememberedAccountProofs.Where(value =>
            value.DeviceId == this.device.Id && value.RevokedAtUtc == null).ToArrayAsync(cancellationToken).ConfigureAwait(false);
        // Include the just-created proof before the transaction flush.
        proofs = [.. proofs.Concat(db.RememberedAccountProofs.Local.Where(value =>
            value.DeviceId == this.device.Id && value.RevokedAtUtc == null)).DistinctBy(value => value.Id)];
        List<RememberedBrowserAccount> accounts = [];
        foreach (RememberedAccountProof proof in proofs.OrderBy(value => value.CreatedAtUtc).Take(options.Value.MaximumAccounts))
        {
            Member? member = await this.FindMemberAsync(proof.MemberId, cancellationToken).ConfigureAwait(false);
            if (member is not null)
            {
                RememberedBrowserAccountProfile? profile = await profiles.FindAsync(
                    member.ScopeId,
                    member.Id.Value,
                    cancellationToken).ConfigureAwait(false);
                accounts.Add(new(proof.Id, Username(member), proof.Label, proof.ExpiresAtUtc,
                    !this.ProofIsValid(proof, member), profile?.DisplayName, profile?.JobTitle));
            }
        }

        bool active = await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false);
        RememberedBrowserActiveAccount? identity = null;
        DateTimeOffset? deadline = null;
        if (active)
        {
            Member member = (await this.FindMemberAsync(this.device.ActiveMemberId, cancellationToken).ConfigureAwait(false))!;
            MemberSession session = member.Sessions.Single(value => value.Id.Value == this.device.ActiveSessionId);
            identity = new(member.Id.Value, session.Id.Value, this.device.ActiveProofId, Username(member),
                proofs.FirstOrDefault(value => value.Id == this.device.ActiveProofId)?.Label);
            deadline = session.AbsoluteExpiresAtUtc;
        }

        RememberedBrowserState state = this.device.State == RememberedBrowserState.Active && !active
            ? RememberedBrowserState.Locked : this.device.State;
        return new(state, this.device.Generation, this.device.PinDigits, accounts, identity,
            active ? this.device.IdleExpiresAtUtc : null, deadline);
    }

    private RememberedBrowserCurrentResponse Empty(RememberedBrowserState state) =>
        new(state, 0, options.Value.PinDigits, [], null, null, null);

    private static string Username(Member member) => member.Usernames.Where(value => value.IsActive)
        .OrderBy(value => value.UsernameType).ThenBy(value => value.Value, StringComparer.Ordinal)
        .Select(value => value.Value).FirstOrDefault() ?? string.Empty;

    internal static string HashCredential(string credential) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left < right ? left : right;
}
