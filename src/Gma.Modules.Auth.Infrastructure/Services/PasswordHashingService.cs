namespace Gma.Modules.Auth.Infrastructure.Services;

using Gma.Modules.Auth.Domain.Services;
using Microsoft.AspNetCore.Identity;

internal sealed class PasswordHashingService : IPasswordHashingService
{
    private readonly PasswordHasher<object> passwordHasher = new();

    public string HashPassword(string password) =>
        this.passwordHasher.HashPassword(new object(), password);

    public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password)
    {
        PasswordVerificationResult result =
            this.passwordHasher.VerifyHashedPassword(new object(), passwordHash, password);

        return result switch
        {
            PasswordVerificationResult.Success => PasswordVerificationOutcome.Success,
            PasswordVerificationResult.SuccessRehashNeeded => PasswordVerificationOutcome.SuccessRehashNeeded,
            _ => PasswordVerificationOutcome.Unknown
        };
    }
}
