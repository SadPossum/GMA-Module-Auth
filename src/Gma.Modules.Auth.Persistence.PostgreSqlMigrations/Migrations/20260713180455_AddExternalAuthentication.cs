using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.PostgreSqlMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalAuthentication : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "PasswordHash",
                schema: "auth",
                table: "members",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(512)",
                oldMaxLength: 512);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "VerificationExpiresAtUtc",
                schema: "auth",
                table: "member_usernames",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "VerificationRequestedAtUtc",
                schema: "auth",
                table: "member_usernames",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VerificationTokenHash",
                schema: "auth",
                table: "member_usernames",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "VerifiedAtUtc",
                schema: "auth",
                table: "member_usernames",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethod",
                schema: "auth",
                table: "member_sessions",
                type: "character varying(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "password");

            migrationBuilder.CreateTable(
                name: "external_authentication_exchanges",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CodeHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Intent = table.Column<int>(type: "integer", nullable: false),
                    Provider = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Issuer = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Subject = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    EmailVerified = table.Column<bool>(type: "boolean", nullable: false),
                    TargetMemberId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetSessionId = table.Column<Guid>(type: "uuid", nullable: true),
                    ReturnUrl = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_external_authentication_exchanges", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "member_external_identities",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Issuer = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Subject = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    IdentityKeyHash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    LinkedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastAuthenticatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_member_external_identities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_member_external_identities_members_MemberId",
                        column: x => x.MemberId,
                        principalSchema: "auth",
                        principalTable: "members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_member_usernames_ScopeId_VerificationTokenHash",
                schema: "auth",
                table: "member_usernames",
                columns: new[] { "ScopeId", "VerificationTokenHash" });

            migrationBuilder.CreateIndex(
                name: "IX_member_sessions_IsActive_SignOutDateTimeUtc",
                schema: "auth",
                table: "member_sessions",
                columns: new[] { "IsActive", "SignOutDateTimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_member_sessions_RefreshTokenExpiresAtUtc",
                schema: "auth",
                table: "member_sessions",
                column: "RefreshTokenExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_external_authentication_exchanges_ExpiresAtUtc",
                schema: "auth",
                table: "external_authentication_exchanges",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_external_authentication_exchanges_ScopeId_CodeHash",
                schema: "auth",
                table: "external_authentication_exchanges",
                columns: new[] { "ScopeId", "CodeHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_external_identities_MemberId",
                schema: "auth",
                table: "member_external_identities",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_member_external_identities_ScopeId_IdentityKeyHash",
                schema: "auth",
                table: "member_external_identities",
                columns: new[] { "ScopeId", "IdentityKeyHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_external_identities_ScopeId_MemberId_Provider",
                schema: "auth",
                table: "member_external_identities",
                columns: new[] { "ScopeId", "MemberId", "Provider" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "external_authentication_exchanges",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "member_external_identities",
                schema: "auth");

            migrationBuilder.DropIndex(
                name: "IX_member_usernames_ScopeId_VerificationTokenHash",
                schema: "auth",
                table: "member_usernames");

            migrationBuilder.DropIndex(
                name: "IX_member_sessions_IsActive_SignOutDateTimeUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropIndex(
                name: "IX_member_sessions_RefreshTokenExpiresAtUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "VerificationExpiresAtUtc",
                schema: "auth",
                table: "member_usernames");

            migrationBuilder.DropColumn(
                name: "VerificationRequestedAtUtc",
                schema: "auth",
                table: "member_usernames");

            migrationBuilder.DropColumn(
                name: "VerificationTokenHash",
                schema: "auth",
                table: "member_usernames");

            migrationBuilder.DropColumn(
                name: "VerifiedAtUtc",
                schema: "auth",
                table: "member_usernames");

            migrationBuilder.DropColumn(
                name: "AuthenticationMethod",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.AlterColumn<string>(
                name: "PasswordHash",
                schema: "auth",
                table: "members",
                type: "character varying(512)",
                maxLength: 512,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "character varying(512)",
                oldMaxLength: 512,
                oldNullable: true);
        }
    }
}
