namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class MemberSessionConfiguration : IEntityTypeConfiguration<MemberSession>
{
    public void Configure(EntityTypeBuilder<MemberSession> builder)
    {
        builder.ToTable("member_sessions");
        builder.HasKey(session => session.Id);

        builder.Property(session => session.Id)
            .HasConversion(id => id.Value, value => new MemberSessionId(value));

        builder.Property(session => session.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));

        builder.Property(session => session.RefreshTokenHash)
            .HasMaxLength(MemberSession.RefreshTokenHashMaxLength)
            .IsRequired();

        builder.Property(session => session.PreviousRefreshTokenHash)
            .HasMaxLength(MemberSession.RefreshTokenHashMaxLength);

        builder.Property(session => session.AuthenticationMethod)
            .HasMaxLength(MemberAuthenticationMethods.MaxLength)
            .HasDefaultValue(MemberAuthenticationMethods.Password)
            .IsRequired();

        builder.Property(session => session.AuthenticationContextReference)
            .HasMaxLength(SessionAuthenticationEvidence.ContextReferenceMaxLength)
            .HasDefaultValue(AuthenticationContextReferences.Legacy)
            .IsRequired();

        builder.Property<string[]>("authenticationMethodReferences")
            .HasField("authenticationMethodReferences")
            .HasColumnName("authentication_method_references")
            .HasConversion(
                values => SessionAuthenticationMethodReferencesJson.Serialize(values),
                value => SessionAuthenticationMethodReferencesJson.Deserialize(value))
            .HasMaxLength(SessionAuthenticationMethodReferencesJson.MaxLength)
            .HasDefaultValue(Array.Empty<string>())
            .IsRequired()
            .Metadata.SetValueComparer(new ValueComparer<string[]>(
                (left, right) => left.SequenceEqual(right),
                values => values.Aggregate(0, (hash, value) => HashCode.Combine(hash, value)),
                values => values.ToArray()));

        builder.Property(session => session.AuthenticatedAtUtc)
            .IsRequired();

        builder.HasIndex(session => new { session.ScopeId, session.RefreshTokenHash });
        builder.HasIndex(session => session.RefreshTokenExpiresAtUtc);
        builder.HasIndex(session => new { session.IsActive, session.SignOutDateTimeUtc });
    }
}
