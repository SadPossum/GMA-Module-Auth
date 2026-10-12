namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Contracts;
using MemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

internal sealed class AuthRememberedSessionAdmissionReader(
    AuthDbContext db,
    IOptions<RememberedBrowserOptions> options,
    ISystemClock clock) : IAuthRememberedSessionAdmissionReader
{
    public async Task<bool> IsAdmittedAsync(
        string scopeId,
        Guid memberId,
        Guid sessionId,
        string? deviceCredential,
        CancellationToken cancellationToken = default)
    {
        var session = await db.MemberSessions.IgnoreQueryFilters().AsNoTracking()
            .Where(value => value.ScopeId == scopeId && value.MemberId == new MemberId(memberId) &&
                value.Id == new MemberSessionId(sessionId))
            .Select(value => new
            {
                value.IsActive,
                value.AbsoluteExpiresAtUtc,
                value.RememberedBrowserDeviceId,
                value.RememberedAccountProofId,
                value.RememberedBrowserGeneration,
                value.RememberedSecurityEpoch
            }).SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        if (session is null || !session.IsActive || session.AbsoluteExpiresAtUtc <= clock.UtcNow)
        {
            return false;
        }

        if (session.RememberedBrowserDeviceId is null && (!options.Value.Enabled || deviceCredential is null))
        {
            return true;
        }

        if (!options.Value.Enabled || deviceCredential is not { Length: 64 } || !deviceCredential.All(char.IsAsciiHexDigit))
        {
            return false;
        }

        string digest = RememberedBrowserService.HashCredential(deviceCredential);
        RememberedBrowserDevice? device = await db.RememberedBrowserDevices.AsNoTracking().SingleOrDefaultAsync(
            value => value.ScopeId == scopeId && value.CredentialHash == digest, cancellationToken).ConfigureAwait(false);
        if (device is null || device.State != RememberedBrowserState.Active || device.RevokedAtUtc is not null ||
            device.RestoreEpoch != options.Value.RestoreEpoch || device.ExpiresAtUtc <= clock.UtcNow ||
            device.IdleExpiresAtUtc is null || device.IdleExpiresAtUtc <= clock.UtcNow ||
            device.ActiveMemberId != memberId || device.ActiveSessionId != sessionId ||
            (session.RememberedBrowserDeviceId is not null &&
            (session.RememberedBrowserDeviceId != device.Id || session.RememberedBrowserGeneration != device.Generation ||
                session.RememberedAccountProofId != device.ActiveProofId)))
        {
            return false;
        }

        var member = await db.Members.IgnoreQueryFilters().AsNoTracking()
            .Where(value => value.Id == new MemberId(memberId) && value.ScopeId == scopeId)
            .Select(value => new { value.Status, value.SecurityEpoch })
            .SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        if (member is null || member.Status != MemberStatus.Active ||
            (session.RememberedSecurityEpoch is not null && session.RememberedSecurityEpoch != member.SecurityEpoch))
        {
            return false;
        }

        return device.ActiveProofId is null || await db.RememberedAccountProofs.AsNoTracking().AnyAsync(
            value => value.Id == device.ActiveProofId && value.ScopeId == scopeId && value.DeviceId == device.Id &&
                value.MemberId == memberId && value.SecurityEpoch == member.SecurityEpoch &&
                value.RevokedAtUtc == null && value.ExpiresAtUtc > clock.UtcNow &&
                value.PepperVersion == options.Value.PepperVersion, cancellationToken).ConfigureAwait(false);
    }
}
