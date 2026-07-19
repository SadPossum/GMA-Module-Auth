namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class MemberMultiFactorFailureAttemptConfiguration
    : IEntityTypeConfiguration<MemberMultiFactorFailureAttempt>
{
    public void Configure(EntityTypeBuilder<MemberMultiFactorFailureAttempt> builder)
    {
        builder.ToTable("member_multi_factor_failure_attempts");
        builder.HasKey(attempt => attempt.Id);

        builder.Property(attempt => attempt.Id)
            .HasConversion(id => id.Value, value => new MemberMultiFactorFailureAttemptId(value));
        builder.Property(attempt => attempt.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));
        builder.Property(attempt => attempt.Purpose)
            .HasMaxLength(MemberMultiFactorFailureAttempt.PurposeMaxLength)
            .IsRequired();
        builder.Property(attempt => attempt.FailedAtUtc).IsRequired();

        builder.HasOne<Member>()
            .WithMany()
            .HasForeignKey(attempt => attempt.MemberId)
            .HasPrincipalKey(member => member.Id)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(attempt => new
        {
            attempt.ScopeId,
            attempt.MemberId,
            attempt.Purpose,
            attempt.FailedAtUtc,
        });
        builder.HasIndex(attempt => attempt.FailedAtUtc);
    }
}
