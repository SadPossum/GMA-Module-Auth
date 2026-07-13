namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class ExternalAuthenticationExchangeRecordConfiguration
    : IEntityTypeConfiguration<ExternalAuthenticationExchangeRecord>
{
    public void Configure(EntityTypeBuilder<ExternalAuthenticationExchangeRecord> builder)
    {
        builder.ToTable("external_authentication_exchanges");
        builder.HasKey(exchange => exchange.Id);

        builder.Property(exchange => exchange.CodeHash)
            .HasMaxLength(MemberSession.RefreshTokenHashMaxLength)
            .IsRequired();

        builder.Property(exchange => exchange.ProviderCode)
            .HasColumnName("Provider")
            .HasMaxLength(MemberExternalIdentity.ProviderMaxLength)
            .IsRequired();

        builder.Property(exchange => exchange.Issuer)
            .HasMaxLength(MemberExternalIdentity.IssuerMaxLength)
            .IsRequired();

        builder.Property(exchange => exchange.Subject)
            .HasMaxLength(MemberExternalIdentity.SubjectMaxLength)
            .IsRequired();

        builder.Property(exchange => exchange.Email)
            .HasMaxLength(MemberUsername.ValueMaxLength);

        builder.Property(exchange => exchange.ReturnUrl)
            .HasMaxLength(2_048)
            .IsRequired();

        builder.Property(exchange => exchange.ConsumedAtUtc)
            .IsConcurrencyToken();

        builder.HasIndex(exchange => new { exchange.ScopeId, exchange.CodeHash })
            .IsUnique();

        builder.HasIndex(exchange => exchange.ExpiresAtUtc);
    }
}
