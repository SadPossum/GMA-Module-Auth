namespace Gma.Modules.Auth.Contracts;

public interface IAuthSubjectStatusReader
{
    ValueTask<AuthSubjectStatusSnapshot?> FindAsync(
        string subjectId,
        CancellationToken cancellationToken = default);
}
