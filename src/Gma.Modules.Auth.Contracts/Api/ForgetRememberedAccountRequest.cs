namespace Gma.Modules.Auth.Contracts;

public sealed record ForgetRememberedAccountRequest(Guid OperationId, long ExpectedGeneration, Guid ProofId);
