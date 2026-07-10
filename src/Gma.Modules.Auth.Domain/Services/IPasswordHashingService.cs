namespace Gma.Modules.Auth.Domain.Services;

public interface IPasswordHashingService
{
    string HashPassword(string password);
    PasswordVerificationOutcome VerifyPassword(string passwordHash, string password);
}

public enum PasswordVerificationOutcome
{
    Unknown = 0,
    Success = 1,
    SuccessRehashNeeded = 2
}
