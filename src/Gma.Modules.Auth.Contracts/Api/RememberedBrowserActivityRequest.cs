namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserActivityRequest(long ExpectedGeneration, Guid SessionId);
