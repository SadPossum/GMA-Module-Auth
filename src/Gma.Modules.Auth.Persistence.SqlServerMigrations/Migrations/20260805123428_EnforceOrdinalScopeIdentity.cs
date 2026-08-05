using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.SqlServerMigrations.Migrations
{
    /// <inheritdoc />
    public partial class EnforceOrdinalScopeIdentity : Migration
    {
        private static readonly ScopeIndexDefinition[] ScopeIndexes =
        [
            new("IX_members_ScopeId_RegisteredAtUtc", "members", ["ScopeId", "RegisteredAtUtc"]),
            new("IX_member_authentication_challenges_ScopeId_TokenHash", "member_authentication_challenges", ["ScopeId", "TokenHash"], true),
            new("IX_member_authentication_challenges_ScopeId_MemberId_CreatedAtUtc", "member_authentication_challenges", ["ScopeId", "MemberId", "CreatedAtUtc"]),
            new("IX_member_multi_factor_failure_attempts_ScopeId_MemberId_Purpose_FailedAtUtc", "member_multi_factor_failure_attempts", ["ScopeId", "MemberId", "Purpose", "FailedAtUtc"]),
            new("IX_member_totp_authenticators_ScopeId_MemberId", "member_totp_authenticators", ["ScopeId", "MemberId"], true),
            new("IX_password_recovery_challenges_ScopeId_TokenHash", "password_recovery_challenges", ["ScopeId", "TokenHash"], true),
            new("IX_password_recovery_challenges_ScopeId_MemberId_RequestedAtUtc", "password_recovery_challenges", ["ScopeId", "MemberId", "RequestedAtUtc"]),
            new("IX_member_external_identities_ScopeId_IdentityKeyHash", "member_external_identities", ["ScopeId", "IdentityKeyHash"], true),
            new("IX_member_external_identities_ScopeId_MemberId_Provider", "member_external_identities", ["ScopeId", "MemberId", "Provider"]),
            new("IX_member_sessions_ScopeId_RefreshTokenHash", "member_sessions", ["ScopeId", "RefreshTokenHash"]),
            new("IX_member_totp_recovery_codes_ScopeId_Hash", "member_totp_recovery_codes", ["ScopeId", "Hash"], true),
            new("IX_member_totp_recovery_codes_ScopeId_MemberId_ConsumedAtUtc", "member_totp_recovery_codes", ["ScopeId", "MemberId", "ConsumedAtUtc"]),
            new("IX_member_usernames_ScopeId_NormalizedValue", "member_usernames", ["ScopeId", "NormalizedValue"], true),
            new("IX_member_usernames_ScopeId_VerificationTokenHash", "member_usernames", ["ScopeId", "VerificationTokenHash"]),
            new("IX_authentication_failure_attempts_ScopeId_Purpose_TargetHash_FailedAtUtc", "authentication_failure_attempts", ["ScopeId", "Purpose", "TargetHash", "FailedAtUtc"]),
            new("IX_external_authentication_exchanges_ScopeId_CodeHash", "external_authentication_exchanges", ["ScopeId", "CodeHash"], true)
        ];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            DropScopeIndexes(migrationBuilder);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "password_recovery_challenges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "outbox_messages",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "members",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_usernames",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_totp_recovery_codes",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_totp_authenticators",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_sessions",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_multi_factor_failure_attempts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_external_identities",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_authentication_challenges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "inbox_messages",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "external_authentication_exchanges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "authentication_failure_attempts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128);

            CreateScopeIndexes(migrationBuilder);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            DropScopeIndexes(migrationBuilder);

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "password_recovery_challenges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "outbox_messages",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "members",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_usernames",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_totp_recovery_codes",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_totp_authenticators",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_sessions",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_multi_factor_failure_attempts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_external_identities",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "member_authentication_challenges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "inbox_messages",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "external_authentication_exchanges",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            migrationBuilder.AlterColumn<string>(
                name: "ScopeId",
                schema: "auth",
                table: "authentication_failure_attempts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldCollation: "Latin1_General_100_BIN2");

            CreateScopeIndexes(migrationBuilder);
        }

        private static void DropScopeIndexes(MigrationBuilder migrationBuilder)
        {
            foreach (ScopeIndexDefinition index in ScopeIndexes)
            {
                migrationBuilder.DropIndex(
                    name: index.Name,
                    schema: "auth",
                    table: index.Table);
            }
        }

        private static void CreateScopeIndexes(MigrationBuilder migrationBuilder)
        {
            foreach (ScopeIndexDefinition index in ScopeIndexes)
            {
                migrationBuilder.CreateIndex(
                    name: index.Name,
                    schema: "auth",
                    table: index.Table,
                    columns: index.Columns,
                    unique: index.Unique);
            }
        }

        private sealed record ScopeIndexDefinition(
            string Name,
            string Table,
            string[] Columns,
            bool Unique = false);
    }
}
