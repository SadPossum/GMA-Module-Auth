namespace Gma.Modules.Auth.Application.Ports;

public sealed record ExternalAuthenticationHandoff(
    string Code,
    string ReturnUrl,
    DateTimeOffset ExpiresAtUtc);
