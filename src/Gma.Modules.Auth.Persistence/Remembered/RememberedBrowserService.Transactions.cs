namespace Gma.Modules.Auth.Persistence.Remembered;

using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed partial class RememberedBrowserService
{
    // Runs inside the existing Auth transaction, before the existing command handler.
    // All session issuance/rotation shares this device row lock with select/lock/recovery.
    internal async Task BeginAsync(CancellationToken cancellationToken)
    {
        this.device = null;
        if (!options.Value.Enabled || request.DeviceCredential is null)
        {
            return;
        }

        this.device = await this.FindDeviceAsync(cancellationToken).ConfigureAwait(false);
        if (this.device is not null && db.Database.IsRelational())
        {
            Guid id = this.device.Id;
            if (db.Database.IsNpgsql())
            {
                await db.Database.ExecuteSqlInterpolatedAsync(
                    $"SELECT 1 FROM auth.remembered_browser_devices WHERE \"Id\" = {id} FOR UPDATE",
                    cancellationToken).ConfigureAwait(false);
            }
            else if (db.Database.IsSqlServer())
            {
                await db.Database.ExecuteSqlInterpolatedAsync(
                    $"SELECT 1 FROM [auth].[remembered_browser_devices] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}",
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                throw new RememberedBrowserStateChangedException();
            }

            await db.Entry(this.device).ReloadAsync(cancellationToken).ConfigureAwait(false);
        }

        if (request.IsRememberedOperation)
        {
            return;
        }

        if (!this.DeviceIsValid() || request.ExpectedGeneration != this.device!.Generation ||
            (this.device.State != RememberedBrowserState.SigningIn &&
            !await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false)))
        {
            throw new RememberedBrowserStateChangedException();
        }

        this.device.Touch();
    }

    // This is before the module's domain events/outbox and SaveChanges, never after commit.
    internal async Task BindIssuedSessionsAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled || request.DeviceCredential is null || request.IsRememberedOperation)
        {
            return;
        }

        if (!this.DeviceIsValid() || request.ExpectedGeneration != this.device!.Generation)
        {
            throw new RememberedBrowserStateChangedException();
        }

        MemberAuthenticationChallenge[] challenges = [.. db.ChangeTracker.Entries<MemberAuthenticationChallenge>()
            .Where(value => value.State == EntityState.Added).Select(value => value.Entity)];
        foreach (MemberAuthenticationChallenge challenge in challenges)
        {
            if (this.device.State != RememberedBrowserState.SigningIn || challenge.ScopeId != this.device.ScopeId)
            {
                throw new RememberedBrowserStateChangedException();
            }

            challenge.BindRememberedBrowser(this.device.Id, this.device.Generation);
        }

        MemberSession[] issued = [.. db.ChangeTracker.Entries<MemberSession>()
            .Where(value => value.State == EntityState.Added && value.Entity.IsActive).Select(value => value.Entity)];
        bool rotated = db.ChangeTracker.Entries<MemberSession>().Any(value =>
            value.State == EntityState.Modified && value.Property(session => session.RefreshTokenHash).IsModified);
        if (!request.IsBrowserTransport && (issued.Length > 0 || rotated))
        {
            throw new RememberedBrowserStateChangedException();
        }

        if (issued.Length > 1 || (issued.Length == 1 && this.device.State != RememberedBrowserState.SigningIn))
        {
            throw new RememberedBrowserStateChangedException();
        }

        if (issued.Length == 1)
        {
            MemberSession session = issued[0];
            Member? member = await this.FindMemberAsync(session.MemberId.Value, cancellationToken).ConfigureAwait(false);
            if (member is null || member.ScopeId != this.device.ScopeId || session.RememberedBrowserDeviceId is not null)
            {
                throw new RememberedBrowserStateChangedException();
            }

            this.Activate(member, session, proofId: null);
        }
    }

    public async Task<bool> AdmitRefreshAsync(Member member, MemberSessionId sessionId, CancellationToken cancellationToken)
    {
        MemberSession? session = member.Sessions.SingleOrDefault(value => value.Id == sessionId);
        if (session is null)
        {
            return false;
        }

        if (session.RememberedBrowserDeviceId is null && request.DeviceCredential is null)
        {
            return true;
        }

        this.device ??= await this.FindDeviceAsync(cancellationToken).ConfigureAwait(false);
        return request.IsBrowserTransport && this.DeviceIsValid() && this.device!.ActiveSessionId == session.Id.Value &&
            this.device.ActiveMemberId == member.Id.Value && request.ExpectedGeneration == this.device.Generation &&
            await this.ActiveIsValidAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> AdmitChallengeAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken)
    {
        if (challenge.RememberedBrowserDeviceId is null)
        {
            return request.DeviceCredential is null;
        }

        this.device ??= await this.FindDeviceAsync(cancellationToken).ConfigureAwait(false);
        return this.DeviceIsValid() && this.device!.State == RememberedBrowserState.SigningIn &&
            challenge.RememberedBrowserDeviceId == this.device.Id && challenge.RememberedBrowserGeneration == this.device.Generation &&
            request.ExpectedGeneration == this.device.Generation;
    }
}
