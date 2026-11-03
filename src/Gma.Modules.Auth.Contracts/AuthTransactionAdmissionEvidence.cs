namespace Gma.Modules.Auth.Contracts;

public sealed record AuthTransactionAdmissionEvidence(AuthTransactionAdmissionRequest Request,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ValidUntilUtc);
