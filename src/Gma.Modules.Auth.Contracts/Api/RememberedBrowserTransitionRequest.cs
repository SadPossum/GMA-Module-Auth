namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserTransitionRequest(Guid OperationId, long ExpectedGeneration);
