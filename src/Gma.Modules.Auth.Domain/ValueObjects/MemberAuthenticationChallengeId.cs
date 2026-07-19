namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct MemberAuthenticationChallengeId
{
    public MemberAuthenticationChallengeId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Authentication challenge id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
