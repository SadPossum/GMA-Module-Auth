namespace Gma.Modules.Auth.Persistence.Configurations;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class AuthenticationAttemptRecordConfiguration
    : IEntityTypeConfiguration<AuthenticationAttemptRecord>
{
    public void Configure(EntityTypeBuilder<AuthenticationAttemptRecord> builder)
    {
        builder.ToTable("authentication_failure_attempts");
        builder.HasKey(attempt => attempt.Id);

        builder.Property(attempt => attempt.Purpose)
            .HasMaxLength(AuthenticationAttemptRecord.PurposeMaxLength)
            .IsRequired();
        builder.Property(attempt => attempt.TargetHash)
            .HasMaxLength(AuthenticationAttemptRecord.TargetHashMaxLength)
            .IsRequired();
        builder.Property(attempt => attempt.FailedAtUtc).IsRequired();

        builder.HasIndex(attempt => new
        {
            attempt.ScopeId,
            attempt.Purpose,
            attempt.TargetHash,
            attempt.FailedAtUtc,
        });
        builder.HasIndex(attempt => attempt.FailedAtUtc);
    }
}
