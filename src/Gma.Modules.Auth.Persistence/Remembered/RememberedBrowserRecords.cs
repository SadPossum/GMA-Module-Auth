namespace Gma.Modules.Auth.Persistence.Remembered;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Application.Ports;

internal sealed class RememberedBrowserDevice
{
    public Guid Id { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public string CredentialHash { get; set; } = string.Empty;
    public long RestoreEpoch { get; set; }
    public long Generation { get; set; } = 1;
    public Guid ConcurrencyStamp { get; set; } = Guid.CreateVersion7();
    public RememberedBrowserState State { get; set; } = RememberedBrowserState.Locked;
    public int PinDigits { get; set; }
    public Guid? ActiveMemberId { get; set; }
    public Guid? ActiveSessionId { get; set; }
    public Guid? ActiveProofId { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset? IdleExpiresAtUtc { get; set; }
    public DateTimeOffset? RevokedAtUtc { get; set; }

    public void Touch() => this.ConcurrencyStamp = Guid.CreateVersion7();
}

internal sealed class RememberedAccountProof
{
    public Guid Id { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public Guid DeviceId { get; set; }
    public Guid MemberId { get; set; }
    public Guid OriginalSessionId { get; set; }
    public long SecurityEpoch { get; set; }
    public string PinHash { get; set; } = string.Empty;
    public string PepperVersion { get; set; } = string.Empty;
    public string? Label { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset AuthenticatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset? RevokedAtUtc { get; set; }
}

internal sealed class RememberedBrowserOperationReceipt
{
    public Guid DeviceId { get; set; }
    public Guid OperationId { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public RememberedBrowserOperationKind Kind { get; set; }
    public long ExpectedGeneration { get; set; }
    public long ResultGeneration { get; set; }
    public Guid? ProofId { get; set; }
    public Guid? MemberId { get; set; }
    public Guid? SessionId { get; set; }
    public RememberedBrowserOutcome Outcome { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
}
