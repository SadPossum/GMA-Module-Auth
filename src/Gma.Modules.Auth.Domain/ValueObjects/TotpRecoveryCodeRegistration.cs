namespace Gma.Modules.Auth.Domain.ValueObjects;

public sealed record TotpRecoveryCodeRegistration(MemberTotpRecoveryCodeId Id, string Hash);
