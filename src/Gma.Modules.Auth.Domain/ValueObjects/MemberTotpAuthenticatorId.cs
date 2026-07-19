namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct MemberTotpAuthenticatorId
{
    public MemberTotpAuthenticatorId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("TOTP authenticator id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
