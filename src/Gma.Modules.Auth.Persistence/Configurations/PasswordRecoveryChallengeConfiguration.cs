namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class PasswordRecoveryChallengeConfiguration
    : IEntityTypeConfiguration<PasswordRecoveryChallenge>
{
    public void Configure(EntityTypeBuilder<PasswordRecoveryChallenge> builder)
    {
        builder.ToTable("password_recovery_challenges");
        builder.HasKey(challenge => challenge.Id);

        builder.Property(challenge => challenge.Id)
            .HasConversion(id => id.Value, value => new PasswordRecoveryChallengeId(value));

        builder.Property(challenge => challenge.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));

        builder.Property(challenge => challenge.Email)
            .HasMaxLength(Domain.Entities.MemberUsername.ValueMaxLength)
            .IsRequired();

        builder.Property(challenge => challenge.TokenHash)
            .HasMaxLength(PasswordRecoveryChallenge.TokenHashMaxLength)
            .IsRequired();

        builder.Property(challenge => challenge.RequestedAtUtc).IsRequired();
        builder.Property(challenge => challenge.ExpiresAtUtc).IsRequired();
        builder.Property(challenge => challenge.ConcurrencyStamp)
            .IsConcurrencyToken()
            .IsRequired();

        builder.HasOne<Member>()
            .WithMany()
            .HasForeignKey(challenge => challenge.MemberId)
            .HasPrincipalKey(member => member.Id)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(challenge => new { challenge.ScopeId, challenge.MemberId, challenge.RequestedAtUtc });
        builder.HasIndex(challenge => new { challenge.ScopeId, challenge.TokenHash }).IsUnique();
        builder.HasIndex(challenge => challenge.ExpiresAtUtc);
        builder.HasIndex(challenge => challenge.ConsumedAtUtc);
        builder.HasIndex(challenge => challenge.RevokedAtUtc);
    }
}
