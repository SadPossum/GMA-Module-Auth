namespace Gma.Modules.Auth.Contracts;

public sealed record AuthSubjectStatusSnapshot(
    string ScopeId,
    string SubjectId,
    MemberStatus Status);
