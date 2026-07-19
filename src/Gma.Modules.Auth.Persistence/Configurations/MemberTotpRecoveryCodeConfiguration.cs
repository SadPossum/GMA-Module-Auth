namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class MemberTotpRecoveryCodeConfiguration
    : IEntityTypeConfiguration<MemberTotpRecoveryCode>
{
    public void Configure(EntityTypeBuilder<MemberTotpRecoveryCode> builder)
    {
        builder.ToTable("member_totp_recovery_codes");
        builder.HasKey(code => code.Id);

        builder.Property(code => code.Id)
            .HasConversion(id => id.Value, value => new MemberTotpRecoveryCodeId(value));

        builder.Property(code => code.AuthenticatorId)
            .HasConversion(id => id.Value, value => new MemberTotpAuthenticatorId(value));

        builder.Property(code => code.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));

        builder.Property(code => code.Hash)
            .HasMaxLength(MemberTotpRecoveryCode.HashMaxLength)
            .IsRequired();

        builder.Property(code => code.GeneratedAtUtc).IsRequired();

        builder.HasIndex(code => new { code.ScopeId, code.Hash }).IsUnique();
        builder.HasIndex(code => new { code.ScopeId, code.MemberId, code.ConsumedAtUtc });
        builder.HasIndex(code => code.RevokedAtUtc);
    }
}
