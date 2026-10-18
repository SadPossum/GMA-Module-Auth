namespace Gma.Modules.Auth.Contracts;

public sealed record SelectRememberedAccountRequest(
    Guid OperationId,
    long ExpectedGeneration,
    Guid ProofId,
    string Pin);
