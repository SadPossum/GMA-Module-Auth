namespace Gma.Modules.Auth.Contracts;

public sealed record RememberBrowserAccountRequest(
    Guid OperationId,
    long ExpectedGeneration,
    string Pin,
    string? Label,
    bool Consent);
