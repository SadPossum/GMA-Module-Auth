namespace Gma.Modules.Auth.Tests;

using System.Text;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Authenticators.Totp;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OtpNet;
using Xunit;

[Trait("Category", "Unit")]
public sealed class TotpAuthenticatorProviderTests
{
    private readonly TotpAuthenticatorProvider provider = new(
        Options.Create(new AuthTotpOptions { Issuer = "Example Hostel" }));

    [Fact]
    public void Verify_matches_rfc_vector_and_reports_time_step()
    {
        byte[] secret = Encoding.ASCII.GetBytes("12345678901234567890");
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(59);

        var result = this.provider.Verify(secret, "287082", timestamp);

        Assert.True(result.IsValid);
        Assert.Equal(1, result.MatchedTimeStep);
    }

    [Fact]
    public void Verify_accepts_only_current_and_previous_steps()
    {
        byte[] secret = KeyGeneration.GenerateRandomKey(20);
        Totp totp = new(secret);
        DateTimeOffset now = new(2026, 7, 19, 10, 0, 30, TimeSpan.Zero);

        var current = this.provider.Verify(secret, totp.ComputeTotp(now.UtcDateTime), now);
        var previous = this.provider.Verify(secret, totp.ComputeTotp(now.AddSeconds(-30).UtcDateTime), now);
        var older = this.provider.Verify(secret, totp.ComputeTotp(now.AddSeconds(-60).UtcDateTime), now);
        var future = this.provider.Verify(secret, totp.ComputeTotp(now.AddSeconds(30).UtcDateTime), now);

        Assert.True(current.IsValid);
        Assert.True(previous.IsValid);
        Assert.False(older.IsValid);
        Assert.False(future.IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12A456")]
    public void Verify_rejects_malformed_codes(string code)
    {
        var result = this.provider.Verify(new byte[20], code, DateTimeOffset.UtcNow);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Generated_secret_and_uri_are_authenticator_compatible()
    {
        var secret = this.provider.GenerateSecret();

        string uri = this.provider.CreateProvisioningUri(
            "user+test@example.com",
            secret.Encoded);

        Assert.Equal(20, secret.Bytes.Length);
        Assert.Equal(secret.Bytes, Base32Encoding.ToBytes(secret.Encoded));
        Assert.StartsWith("otpauth://totp/Example%20Hostel:user%2Btest%40example.com?", uri, StringComparison.Ordinal);
        Assert.Contains($"secret={secret.Encoded}", uri, StringComparison.Ordinal);
        Assert.Contains("issuer=Example%20Hostel", uri, StringComparison.Ordinal);
        Assert.Contains("algorithm=SHA1", uri, StringComparison.Ordinal);
        Assert.Contains("digits=6", uri, StringComparison.Ordinal);
        Assert.Contains("period=30", uri, StringComparison.Ordinal);
    }

    [Fact]
    public void Data_protection_adapter_round_trips_and_rejects_tampering()
    {
        DataProtectionAuthenticatorSecretProtector protector = new(new EphemeralDataProtectionProvider());
        byte[] secret = KeyGeneration.GenerateRandomKey(20);

        string protectedSecret = protector.Protect(secret);

        Assert.Equal(secret, protector.Unprotect(protectedSecret));
        Assert.ThrowsAny<Exception>(() => protector.Unprotect(protectedSecret + "tampered"));
    }

    [Fact]
    public void Options_require_a_bounded_issuer()
    {
        AuthTotpOptionsValidator validator = new();

        Assert.True(validator.Validate(null, new AuthTotpOptions()).Succeeded);
        Assert.True(validator.Validate(null, new AuthTotpOptions { Issuer = " " }).Failed);
        Assert.True(validator.Validate(
            null,
            new AuthTotpOptions { Issuer = new string('x', AuthTotpOptions.IssuerMaxLength + 1) }).Failed);
    }

    [Fact]
    public void Adapter_explicitly_replaces_auths_fail_closed_ports()
    {
        IHostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Services.AddAuthApplication(builder.Configuration);
        builder.AddAuthTotpAuthenticator();

        using ServiceProvider services = builder.Services.BuildServiceProvider();

        Assert.IsType<TotpAuthenticatorProvider>(services.GetRequiredService<ITimeBasedOneTimePasswordProvider>());
        Assert.IsType<DataProtectionAuthenticatorSecretProtector>(services.GetRequiredService<IAuthenticatorSecretProtector>());
    }
}
