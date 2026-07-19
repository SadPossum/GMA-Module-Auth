namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct MemberTotpRecoveryCodeId
{
    public MemberTotpRecoveryCodeId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("TOTP recovery code id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
