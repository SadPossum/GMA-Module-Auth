namespace Gma.Modules.Auth.Domain.ValueObjects;

public readonly record struct MemberExternalIdentityId
{
    public MemberExternalIdentityId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Member external identity id is required.", nameof(value));
        }

        this.Value = value;
    }

    public Guid Value { get; }
}
