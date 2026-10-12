namespace Gma.Modules.Auth.Persistence.Configurations;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

internal sealed class RememberedBrowserConfiguration :
    IEntityTypeConfiguration<RememberedBrowserDevice>,
    IEntityTypeConfiguration<RememberedAccountProof>,
    IEntityTypeConfiguration<RememberedBrowserOperationReceipt>
{
    public void Configure(EntityTypeBuilder<RememberedBrowserDevice> builder)
    {
        builder.ToTable("remembered_browser_devices");
        builder.HasKey(value => value.Id);
        builder.Property(value => value.ScopeId).HasMaxLength(128).IsRequired();
        builder.Property(value => value.CredentialHash).HasMaxLength(64).IsRequired();
        builder.Property(value => value.ConcurrencyStamp).IsConcurrencyToken();
        builder.HasIndex(value => value.CredentialHash).IsUnique();
        builder.HasIndex(value => value.ExpiresAtUtc);
    }

    public void Configure(EntityTypeBuilder<RememberedAccountProof> builder)
    {
        builder.ToTable("remembered_account_proofs");
        builder.HasKey(value => value.Id);
        builder.Property(value => value.ScopeId).HasMaxLength(128).IsRequired();
        builder.Property(value => value.PinHash).HasMaxLength(Member.PasswordHashMaxLength).IsRequired();
        builder.Property(value => value.PepperVersion).HasMaxLength(64).IsRequired();
        builder.Property(value => value.Label).HasMaxLength(MemberUsername.ValueMaxLength);
        builder.HasIndex(value => new { value.DeviceId, value.MemberId }).IsUnique();
        builder.HasIndex(value => new { value.ScopeId, value.MemberId });
        builder.HasIndex(value => value.ExpiresAtUtc);
        builder.HasOne<RememberedBrowserDevice>().WithMany().HasForeignKey(value => value.DeviceId).OnDelete(DeleteBehavior.Cascade);
    }

    public void Configure(EntityTypeBuilder<RememberedBrowserOperationReceipt> builder)
    {
        builder.ToTable("remembered_browser_operations");
        builder.HasKey(value => new { value.DeviceId, value.OperationId });
        builder.Property(value => value.ScopeId).HasMaxLength(128).IsRequired();
        builder.HasIndex(value => new { value.ScopeId, value.MemberId });
        builder.HasOne<RememberedBrowserDevice>().WithMany().HasForeignKey(value => value.DeviceId).OnDelete(DeleteBehavior.Cascade);
    }
}
