namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class MemberTotpAuthenticatorConfiguration
    : IEntityTypeConfiguration<MemberTotpAuthenticator>
{
    public void Configure(EntityTypeBuilder<MemberTotpAuthenticator> builder)
    {
        builder.ToTable("member_totp_authenticators");
        builder.HasKey(authenticator => authenticator.Id);

        builder.Property(authenticator => authenticator.Id)
            .HasConversion(id => id.Value, value => new MemberTotpAuthenticatorId(value));

        builder.Property(authenticator => authenticator.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));

        builder.Property(authenticator => authenticator.ProtectedSecret)
            .IsUnicode(false)
            .HasMaxLength(MemberTotpAuthenticator.ProtectedSecretMaxLength);

        builder.Property(authenticator => authenticator.EnrollmentStartedAtUtc).IsRequired();
        builder.Property(authenticator => authenticator.EnrollmentExpiresAtUtc).IsRequired();
        builder.Property(authenticator => authenticator.ConcurrencyStamp)
            .IsConcurrencyToken()
            .IsRequired();

        builder.HasOne<Member>()
            .WithMany()
            .HasForeignKey(authenticator => authenticator.MemberId)
            .HasPrincipalKey(member => member.Id)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(authenticator => authenticator.RecoveryCodes)
            .WithOne()
            .HasForeignKey(code => code.AuthenticatorId)
            .HasPrincipalKey(authenticator => authenticator.Id)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Navigation(authenticator => authenticator.RecoveryCodes)
            .UsePropertyAccessMode(PropertyAccessMode.Field);

        builder.HasIndex(authenticator => new { authenticator.ScopeId, authenticator.MemberId }).IsUnique();
        builder.HasIndex(authenticator => authenticator.EnrollmentExpiresAtUtc);
        builder.HasIndex(authenticator => authenticator.ActivatedAtUtc);
        builder.HasIndex(authenticator => authenticator.DisabledAtUtc);
    }
}
