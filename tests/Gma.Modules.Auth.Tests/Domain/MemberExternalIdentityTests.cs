namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Domain.Entities;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MemberExternalIdentityTests
{
    [Fact]
    public void Identity_key_hash_is_stable_trimmed_and_fixed_length()
    {
        string first = MemberExternalIdentity.CreateIdentityKeyHash(" https://issuer.example ", " subject-1 ");
        string second = MemberExternalIdentity.CreateIdentityKeyHash("https://issuer.example", "subject-1");

        Assert.Equal(first, second);
        Assert.Equal(MemberExternalIdentity.IdentityKeyHashLength, first.Length);
        Assert.All(first, character => Assert.True(Uri.IsHexDigit(character)));
    }

    [Fact]
    public void Identity_key_hash_uses_unambiguous_length_prefixed_components()
    {
        string first = MemberExternalIdentity.CreateIdentityKeyHash("a", "bc");
        string second = MemberExternalIdentity.CreateIdentityKeyHash("ab", "c");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Identity_key_hash_preserves_exact_identity_case_semantics()
    {
        string first = MemberExternalIdentity.CreateIdentityKeyHash("https://issuer.example", "Subject-1");
        string second = MemberExternalIdentity.CreateIdentityKeyHash("https://issuer.example", "subject-1");

        Assert.NotEqual(first, second);
    }

}
