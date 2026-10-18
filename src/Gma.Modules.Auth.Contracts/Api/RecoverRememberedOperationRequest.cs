namespace Gma.Modules.Auth.Contracts;

public sealed record RecoverRememberedOperationRequest(
    Guid OperationId,
    long ExpectedGeneration,
    string Pin);
