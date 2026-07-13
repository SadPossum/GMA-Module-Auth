namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application.ExternalAuthentication;
using Xunit;

[Trait("Category", "Unit")]
public sealed class ValidatedExternalIdentityTests
{
    [Fact]
    public void Invalid_provider_email_is_ignored_instead_of_breaking_existing_identity_sign_in()
    {
        var identity = new ValidatedExternalIdentity(
            "google",
            "https://accounts.google.com",
            "subject-1",
            "not-an-email",
            emailVerified: true);

        Assert.Null(identity.Email);
        Assert.False(identity.EmailVerified);
    }

    [Fact]
    public void Verified_email_is_normalized_without_changing_its_display_value()
    {
        var identity = new ValidatedExternalIdentity(
            "Google",
            " https://accounts.google.com ",
            " subject-1 ",
            " Member@example.com ",
            emailVerified: true);

        Assert.Equal("google", identity.ProviderCode);
        Assert.Equal("https://accounts.google.com", identity.Issuer);
        Assert.Equal("subject-1", identity.Subject);
        Assert.Equal("Member@example.com", identity.Email);
        Assert.True(identity.EmailVerified);
    }

    [Fact]
    public void Identity_components_reject_control_characters_before_persistence()
    {
        Assert.Throws<ArgumentException>(() => new ValidatedExternalIdentity(
            "google",
            "https://accounts.google.com",
            "subject\n2",
            "member@example.com",
            emailVerified: true));
    }
}
