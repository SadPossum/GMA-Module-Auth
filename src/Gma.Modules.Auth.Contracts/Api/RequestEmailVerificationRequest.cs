namespace Gma.Modules.Auth.Contracts;

public sealed record RequestEmailVerificationRequest(Guid? EmailId = null);
