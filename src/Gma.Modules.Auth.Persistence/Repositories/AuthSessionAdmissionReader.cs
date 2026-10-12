namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Naming;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Application;
using Microsoft.Extensions.Options;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using DomainMemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;

internal sealed class AuthSessionAdmissionReader(
    AuthDbContext dbContext,
    ISystemClock clock,
    IOptions<RememberedBrowserOptions>? rememberedOptions = null) : IAuthSessionAdmissionReader
{
    public async ValueTask<bool> IsActiveAsync(
        string scopeId,
        Guid memberId,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        if (memberId == Guid.Empty || sessionId == Guid.Empty)
        {
            return false;
        }

        MemberId expectedMemberId = new(memberId);
        MemberSessionId expectedSessionId = new(sessionId);
        DateTimeOffset nowUtc = clock.UtcNow;
        bool rememberedEnabled = rememberedOptions?.Value.Enabled == true;
        long restoreEpoch = rememberedOptions?.Value.RestoreEpoch ?? 0;
        string pepperVersion = rememberedOptions?.Value.PepperVersion ?? string.Empty;

        return await dbContext.MemberSessions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(session =>
                session.Id == expectedSessionId &&
                session.MemberId == expectedMemberId &&
                session.ScopeId == normalizedScopeId &&
                session.IsActive &&
                session.AbsoluteExpiresAtUtc > nowUtc)
            .AnyAsync(session => dbContext.Members
                .IgnoreQueryFilters()
                .Any(member =>
                    member.Id == session.MemberId &&
                    member.ScopeId == normalizedScopeId &&
                    member.Status == DomainMemberStatus.Active &&
                    (session.RememberedBrowserDeviceId == null ||
                        (rememberedEnabled && session.RememberedSecurityEpoch == member.SecurityEpoch &&
                            dbContext.RememberedBrowserDevices.Any(device =>
                                device.Id == session.RememberedBrowserDeviceId && device.ScopeId == normalizedScopeId &&
                                device.RestoreEpoch == restoreEpoch && device.RevokedAtUtc == null &&
                                device.State == RememberedBrowserState.Active && device.ExpiresAtUtc > nowUtc &&
                                device.IdleExpiresAtUtc > nowUtc && device.ActiveMemberId == memberId &&
                                device.ActiveSessionId == sessionId && device.Generation == session.RememberedBrowserGeneration &&
                                device.ActiveProofId == session.RememberedAccountProofId &&
                                (device.ActiveProofId == null || dbContext.RememberedAccountProofs.Any(proof =>
                                    proof.Id == device.ActiveProofId && proof.DeviceId == device.Id && proof.ScopeId == normalizedScopeId &&
                                    proof.MemberId == memberId && proof.SecurityEpoch == member.SecurityEpoch &&
                                    proof.RevokedAtUtc == null && proof.ExpiresAtUtc > nowUtc &&
                                    proof.PepperVersion == pepperVersion)))))),
                cancellationToken)
            .ConfigureAwait(false);
    }
}
