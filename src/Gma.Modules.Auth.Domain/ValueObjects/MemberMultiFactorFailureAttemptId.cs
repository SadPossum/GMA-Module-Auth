namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct MemberMultiFactorFailureAttemptId
{
    public MemberMultiFactorFailureAttemptId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Multi-factor failure attempt id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
