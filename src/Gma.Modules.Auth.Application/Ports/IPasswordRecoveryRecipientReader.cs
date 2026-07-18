namespace Gma.Modules.Auth.Application.Ports;

public interface IPasswordRecoveryRecipientReader
{
    Task<PasswordRecoveryRecipient?> FindEligibleByEmailAsync(
        string email,
        CancellationToken cancellationToken);
}

public sealed record PasswordRecoveryRecipient(Guid MemberId, string ScopeId, string Email);
