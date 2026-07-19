namespace Gma.Modules.Auth.Contracts;

public sealed record TotpEnrollmentResponse(
    string Secret,
    string ProvisioningUri,
    DateTimeOffset ExpiresAtUtc);
