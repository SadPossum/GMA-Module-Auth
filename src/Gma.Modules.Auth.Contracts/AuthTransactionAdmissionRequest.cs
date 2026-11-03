namespace Gma.Modules.Auth.Contracts;

/// <summary>Identity/session facts only; this is not financial permission, history certification,
/// or permission to act for another subject. The caller separately binds its authenticated actor.</summary>
public sealed record AuthTransactionAdmissionRequest(string ScopeId, Guid MemberId, Guid SessionId);
