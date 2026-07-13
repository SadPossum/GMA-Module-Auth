namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class MemberExternalIdentityConfiguration : IEntityTypeConfiguration<MemberExternalIdentity>
{
    public void Configure(EntityTypeBuilder<MemberExternalIdentity> builder)
    {
        builder.ToTable("member_external_identities");
        builder.HasKey(identity => identity.Id);

        builder.Property(identity => identity.Id)
            .HasConversion(id => id.Value, value => new MemberExternalIdentityId(value));

        builder.Property(identity => identity.MemberId)
            .HasConversion(id => id.Value, value => new MemberId(value));

        builder.Property(identity => identity.ProviderCode)
            .HasColumnName("Provider")
            .HasMaxLength(MemberExternalIdentity.ProviderMaxLength)
            .IsRequired();

        builder.Property(identity => identity.Issuer)
            .HasMaxLength(MemberExternalIdentity.IssuerMaxLength)
            .IsRequired();

        builder.Property(identity => identity.Subject)
            .HasMaxLength(MemberExternalIdentity.SubjectMaxLength)
            .IsRequired();

        builder.Property(identity => identity.IdentityKeyHash)
            .HasMaxLength(MemberExternalIdentity.IdentityKeyHashLength)
            .IsFixedLength()
            .IsRequired();

        builder.HasIndex(identity => new { identity.ScopeId, identity.IdentityKeyHash })
            .IsUnique();

        builder.HasIndex(identity => new { identity.ScopeId, identity.MemberId, identity.ProviderCode });
    }
}
