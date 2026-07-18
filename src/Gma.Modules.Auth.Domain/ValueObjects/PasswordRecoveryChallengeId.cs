namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct PasswordRecoveryChallengeId
{
    public PasswordRecoveryChallengeId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Password recovery challenge id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
