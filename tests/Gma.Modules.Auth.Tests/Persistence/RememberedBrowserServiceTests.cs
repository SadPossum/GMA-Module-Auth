namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Remembered;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;
using UsernameType = Gma.Modules.Auth.Domain.Enums.MemberUsernameType;

[Trait("Category", "Unit")]
public sealed class RememberedBrowserServiceTests
{
    [Fact]
    public async Task Ordinary_real_account_without_MFA_or_Staff_self_remembers_and_preserves_initial_evidence()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        Assert.Equal(RememberedBrowserOutcome.Applied, remembered.Response.Outcome);
        Assert.False(test.Original.IsActive);
        MemberSession child = test.Child(remembered);
        Assert.Equal(test.Original.AuthenticatedAtUtc, child.AuthenticatedAtUtc);
        Assert.Equal(test.Original.AbsoluteExpiresAtUtc, child.AbsoluteExpiresAtUtc);
        Assert.Equal(test.Original.AuthenticationContextReference, child.AuthenticationContextReference);
        Assert.Equal(test.Original.AuthenticationMethodReferences, child.AuthenticationMethodReferences);
        Assert.Equal(test.Member.Id.Value, remembered.Response.Current.Active!.MemberId);
        Assert.Equal("Self chosen name", Assert.Single(remembered.Response.Current.Accounts).Label);
        Assert.Equal("own@example.test", Assert.Single(remembered.Response.Current.Accounts).Username);
        Assert.NotNull(remembered.RefreshToken);
    }

    [Fact]
    public async Task PIN_selection_is_low_assurance_and_never_extends_initial_deadline()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        Guid proof = remembered.Response.Current.Active!.ProofId!.Value;
        await test.RunAsync(new(RememberedBrowserOperationKind.Lock, Guid.NewGuid(), remembered.Response.Current.Generation));
        RememberedBrowserCompletion selected = await test.SelectAsync(proof);
        MemberSession child = test.Child(selected);
        Assert.Equal(MemberAuthenticationMethods.DevicePin, child.AuthenticationMethod);
        Assert.Equal(AuthenticationContextReferences.DevicePin, child.AuthenticationContextReference);
        Assert.Equal([AuthenticationMethodReferences.DevicePin], child.AuthenticationMethodReferences);
        Assert.Equal(test.Original.AuthenticatedAtUtc, child.AuthenticatedAtUtc);
        Assert.Equal(test.Original.AbsoluteExpiresAtUtc, child.AbsoluteExpiresAtUtc);
    }

    [Fact]
    public async Task Lost_select_recovery_reissues_only_the_same_child_and_superseded_delivery_is_not_refresh_theft()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        Guid proof = remembered.Response.Current.Active!.ProofId!.Value;
        Guid operationId = Guid.NewGuid();
        long generation = remembered.Response.Current.Generation;
        RememberedBrowserCompletion selected = await test.RunAsync(new(RememberedBrowserOperationKind.Select,
            operationId, generation, ProofId: proof, Pin: Harness.Pin));
        MemberSession child = test.Child(selected);
        string originalHash = child.RefreshTokenHash;
        int count = test.Member.Sessions.Count;
        RememberedBrowserOperationResponse receipt = await test.Service.OutcomeAsync(operationId, CancellationToken.None);
        Assert.Equal(RememberedBrowserOutcome.Applied, receipt.Outcome);
        Assert.Null(receipt.AccessToken);
        RememberedBrowserCompletion recovered = await test.RunAsync(new(RememberedBrowserOperationKind.Recover,
            operationId, generation, Pin: Harness.Pin));
        Assert.Equal(child.Id.Value, recovered.Response.Current.Active!.SessionId);
        Assert.Equal(count, test.Member.Sessions.Count);
        Assert.NotEqual(originalHash, child.RefreshTokenHash);
        Assert.Null(child.PreviousRefreshTokenHash);
        Assert.True(test.Member.RefreshSession(child.Id, [originalHash], "next-hash",
            test.Clock.UtcNow.AddDays(1), Guid.NewGuid(), test.Clock.UtcNow).IsFailure);
        Assert.True(child.IsActive);
    }

    [Fact]
    public async Task Later_lock_fences_stale_recovery_without_delivering_credentials()
    {
        await using Harness test = await Harness.CreateAsync();
        Guid rememberId = Guid.NewGuid();
        long initial = (await test.Service.CurrentAsync(CancellationToken.None)).Generation;
        RememberedBrowserCompletion remembered = await test.RememberAsync(rememberId);
        await test.RunAsync(new(RememberedBrowserOperationKind.Lock, Guid.NewGuid(), remembered.Response.Current.Generation));
        RememberedBrowserCompletion recovered = await test.RunAsync(new(RememberedBrowserOperationKind.Recover,
            rememberId, initial, Pin: Harness.Pin));
        Assert.Equal(RememberedBrowserOutcome.StateChanged, recovered.Response.Outcome);
        Assert.Null(recovered.RefreshToken);
        Assert.Null(recovered.Response.AccessToken);
        Assert.False(test.Child(remembered).IsActive);
    }

    [Fact]
    public async Task Lock_first_rejects_original_remember_coordinates_without_adding_proof_child_or_receipt()
    {
        await using Harness test = await Harness.CreateAsync();
        long initial = (await test.Service.CurrentAsync(CancellationToken.None)).Generation;
        await test.RunAsync(new(RememberedBrowserOperationKind.Lock, Guid.NewGuid(), initial));
        Guid rememberId = Guid.NewGuid();
        RememberedBrowserCompletion late = await test.RunAsync(new(RememberedBrowserOperationKind.Remember,
            rememberId, initial, test.Member.Id.Value, test.Original.Id.Value, Pin: Harness.Pin, Consent: true));
        Assert.Equal(RememberedBrowserOutcome.StateChanged, late.Response.Outcome);
        Assert.Empty(await test.Db.RememberedAccountProofs.ToArrayAsync());
        Assert.Single(test.Member.Sessions);
        Assert.DoesNotContain(await test.Db.RememberedBrowserOperations.ToArrayAsync(), value => value.OperationId == rememberId);
    }

    [Fact]
    public async Task Remember_first_rejects_old_lock_then_current_generation_lock_closes_child()
    {
        await using Harness test = await Harness.CreateAsync();
        long initial = (await test.Service.CurrentAsync(CancellationToken.None)).Generation;
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        RememberedBrowserCompletion oldLock = await test.RunAsync(new(RememberedBrowserOperationKind.Lock, Guid.NewGuid(), initial));
        Assert.Equal(RememberedBrowserOutcome.StateChanged, oldLock.Response.Outcome);
        Assert.True(test.Child(remembered).IsActive);
        RememberedBrowserCompletion currentLock = await test.RunAsync(new(RememberedBrowserOperationKind.Lock,
            Guid.NewGuid(), remembered.Response.Current.Generation));
        Assert.Equal(RememberedBrowserOutcome.Applied, currentLock.Response.Outcome);
        Assert.False(test.Child(remembered).IsActive);
    }

    [Fact]
    public async Task Idle_is_not_renewed_by_current_or_refresh_and_only_matching_foreground_activity_renews_it()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        DateTimeOffset? originalIdle = remembered.Response.Current.IdleExpiresAtUtc;
        test.Clock.UtcNow = test.Clock.UtcNow.AddMinutes(1);
        Assert.Equal(originalIdle, (await test.Service.CurrentAsync(CancellationToken.None)).IdleExpiresAtUtc);
        RememberedBrowserCompletion wrong = await test.RunAsync(new(RememberedBrowserOperationKind.Activity,
            Guid.Empty, remembered.Response.Current.Generation, test.Member.Id.Value, Guid.NewGuid()));
        Assert.Equal(RememberedBrowserOutcome.StateChanged, wrong.Response.Outcome);
        RememberedBrowserCompletion activity = await test.RunAsync(new(RememberedBrowserOperationKind.Activity,
            Guid.Empty, remembered.Response.Current.Generation, test.Member.Id.Value, test.Child(remembered).Id.Value));
        Assert.Equal(originalIdle!.Value.AddMinutes(1), activity.Response.Current.IdleExpiresAtUtc);
        test.Clock.UtcNow = test.Clock.UtcNow.AddMinutes(6);
        Assert.Equal(RememberedBrowserState.Locked, (await test.Service.CurrentAsync(CancellationToken.None)).State);
        AuthSessionAdmissionReader reader = new(test.Db, test.Clock, test.Settings);
        Assert.False(await reader.IsActiveAsync("global", test.Member.Id.Value, test.Child(remembered).Id.Value));
    }

    [Fact]
    public async Task Security_epoch_invalidates_proof_and_current_child_without_affecting_unbound_sessions()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCompletion remembered = await test.RememberAsync();
        test.Member.InvalidateRememberedAccounts();
        await test.Db.SaveChangesAsync();
        RememberedBrowserCurrentResponse current = await test.Service.CurrentAsync(CancellationToken.None);
        Assert.Equal(RememberedBrowserState.Locked, current.State);
        Assert.True(Assert.Single(current.Accounts).RequiresSignIn);
        RememberedBrowserCompletion selected = await test.SelectAsync(remembered.Response.Current.Active!.ProofId!.Value);
        Assert.Equal(RememberedBrowserOutcome.AuthenticationRequired, selected.Response.Outcome);
    }

    [Fact]
    public async Task Unknown_recovery_is_metadata_only_and_does_not_mint_a_session()
    {
        await using Harness test = await Harness.CreateAsync();
        RememberedBrowserCurrentResponse current = await test.Service.CurrentAsync(CancellationToken.None);
        RememberedBrowserCompletion recovery = await test.RunAsync(new(RememberedBrowserOperationKind.Recover,
            Guid.NewGuid(), current.Generation, Pin: Harness.Pin));
        Assert.Equal(RememberedBrowserOutcome.NotFound, recovery.Response.Outcome);
        Assert.Null(recovery.RefreshToken);
        Assert.Null(recovery.Response.AccessToken);
        Assert.Single(test.Member.Sessions);
    }

    private sealed class Harness : IAsyncDisposable
    {
        public const string Pin = "482619";
        private readonly RememberedBrowserRequestContext request = new() { IsRememberedOperation = true };
        private readonly RememberedPinKdfCapacity capacity;
        public MutableClock Clock { get; } = new();
        public AuthDbContext Db { get; }
        public Member Member { get; }
        public MemberSession Original { get; }
        public RememberedBrowserService Service { get; }
        public IOptions<RememberedBrowserOptions> Settings { get; } = Options.Create(new RememberedBrowserOptions
        {
            Enabled = true,
            RestoreEpoch = 1,
            PepperVersion = "test-only",
            Pepper = Convert.ToBase64String(new byte[32])
        });

        private Harness()
        {
            TestScope scope = new();
            this.Db = new(new DbContextOptionsBuilder<AuthDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options, scope);
            this.Member = Member.Create(new(Guid.NewGuid()), "global", "own@example.test", UsernameType.Email,
                "password-hash", new(Guid.NewGuid()), Guid.NewGuid(), this.Clock.UtcNow).Value;
            this.Original = this.Member.StartSession(new(Guid.NewGuid()), "original-hash", this.Clock.UtcNow.AddDays(30),
                this.Clock.UtcNow, authenticationEvidence: SessionAuthenticationEvidence.Password(this.Clock.UtcNow),
                absoluteExpiresAtUtc: this.Clock.UtcNow.AddDays(90)).Value;
            this.capacity = new(this.Settings);
            this.Service = new(this.Db, this.request, scope, this.Settings, Options.Create(new AuthApplicationOptions()),
                new MemberRepository(this.Db, this.Clock), new(this.Settings, new FastTestPasswordHasher(), this.capacity),
                new ProcessLocalAuthenticationAttemptLimiter(), new TestTokens(), new TestRefreshHashes(), this.Clock,
                new EmptyRememberedBrowserAccountProfileReader());
        }

        public static async Task<Harness> CreateAsync()
        {
            Harness test = new();
            test.Db.Members.Add(test.Member);
            await test.Db.SaveChangesAsync();
            RememberedBrowserCompletion bootstrap = await test.RunAsync(new(RememberedBrowserOperationKind.Device,
                Guid.Empty, 0, test.Member.Id.Value, test.Original.Id.Value));
            Assert.Equal(RememberedBrowserOutcome.Applied, bootstrap.Response.Outcome);
            Assert.Equal(test.Original.Id.Value, bootstrap.Response.Current.Active!.SessionId);
            test.request.DeviceCredential = bootstrap.DeviceCredential;
            return test;
        }

        public async Task<RememberedBrowserCompletion> RememberAsync(Guid? operationId = null)
        {
            RememberedBrowserCurrentResponse current = await this.Service.CurrentAsync(CancellationToken.None);
            return await this.RunAsync(new(RememberedBrowserOperationKind.Remember, operationId ?? Guid.NewGuid(),
                current.Generation, this.Member.Id.Value, this.Original.Id.Value, Pin: Pin, Label: "  Self chosen name  ", Consent: true));
        }

        public async Task<RememberedBrowserCompletion> SelectAsync(Guid proof)
        {
            RememberedBrowserCurrentResponse current = await this.Service.CurrentAsync(CancellationToken.None);
            return await this.RunAsync(new(RememberedBrowserOperationKind.Select, Guid.NewGuid(), current.Generation, ProofId: proof, Pin: Pin));
        }

        public async Task<RememberedBrowserCompletion> RunAsync(RememberedBrowserOperation operation)
        {
            this.request.ExpectedGeneration = (await this.Service.CurrentAsync(CancellationToken.None)).Generation;
            await this.Service.BeginAsync(CancellationToken.None);
            RememberedBrowserCompletion result = await this.Service.ExecuteAsync(operation, CancellationToken.None);
            await this.Service.BindIssuedSessionsAsync(CancellationToken.None);
            await this.Db.SaveChangesAsync();
            return result;
        }

        public MemberSession Child(RememberedBrowserCompletion completion) =>
            this.Member.Sessions.Single(value => value.Id.Value == completion.Response.Current.Active!.SessionId);

        public async ValueTask DisposeAsync()
        {
            this.capacity.Dispose();
            await this.Db.DisposeAsync();
        }
    }

    private sealed class MutableClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class TestScope : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "global";
        public bool TryRestoreScope(string? scopeId) => scopeId == "global";
    }

    private sealed class FastTestPasswordHasher : IPasswordHashingService
    {
        public string HashPassword(string password) => "test-hash:" + password;
        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            passwordHash == this.HashPassword(password) ? PasswordVerificationOutcome.Success : PasswordVerificationOutcome.Unknown;
    }

    private sealed class TestRefreshHashes : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) => "refresh-hash:" + refreshToken;
        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) => [this.HashRefreshToken(refreshToken)];
    }

    private sealed class TestTokens : ITokenService
    {
        public string GenerateAccessToken(AccessTokenClaims claims) => "test-access-" + claims.SessionId.Value;
        public string GenerateRefreshToken() => Guid.NewGuid().ToString("N");
        public MemberId? GetMemberId(string accessToken, bool validateLifetime) => null;
        public AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime) => null;
    }
}
