using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.PostgreSqlMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddTotpMultiFactorAuthentication : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "member_authentication_challenges",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    PrimaryAuthenticationMethod = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PrimaryAuthenticationContextReference = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PrimaryAuthenticatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    FailedAttemptCount = table.Column<int>(type: "integer", nullable: false),
                    MaximumAttempts = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ConcurrencyStamp = table.Column<Guid>(type: "uuid", nullable: false),
                    primary_authentication_method_references = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_member_authentication_challenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_member_authentication_challenges_members_MemberId",
                        column: x => x.MemberId,
                        principalSchema: "auth",
                        principalTable: "members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "member_multi_factor_failure_attempts",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    Purpose = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FailedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_member_multi_factor_failure_attempts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_member_multi_factor_failure_attempts_members_MemberId",
                        column: x => x.MemberId,
                        principalSchema: "auth",
                        principalTable: "members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "member_totp_authenticators",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProtectedSecret = table.Column<string>(type: "character varying(4096)", unicode: false, maxLength: 4096, nullable: true),
                    EnrollmentStartedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    EnrollmentExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ActivatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    DisabledAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RecoveryCodesRegeneratedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAcceptedTimeStep = table.Column<long>(type: "bigint", nullable: true),
                    ConcurrencyStamp = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_member_totp_authenticators", x => x.Id);
                    table.ForeignKey(
                        name: "FK_member_totp_authenticators_members_MemberId",
                        column: x => x.MemberId,
                        principalSchema: "auth",
                        principalTable: "members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "member_totp_recovery_codes",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthenticatorId = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    Hash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    GeneratedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_member_totp_recovery_codes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_member_totp_recovery_codes_member_totp_authenticators_Authe~",
                        column: x => x.AuthenticatorId,
                        principalSchema: "auth",
                        principalTable: "member_totp_authenticators",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_ConsumedAtUtc",
                schema: "auth",
                table: "member_authentication_challenges",
                column: "ConsumedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_ExpiresAtUtc",
                schema: "auth",
                table: "member_authentication_challenges",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_MemberId",
                schema: "auth",
                table: "member_authentication_challenges",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_RevokedAtUtc",
                schema: "auth",
                table: "member_authentication_challenges",
                column: "RevokedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_ScopeId_MemberId_CreatedAt~",
                schema: "auth",
                table: "member_authentication_challenges",
                columns: new[] { "ScopeId", "MemberId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_member_authentication_challenges_ScopeId_TokenHash",
                schema: "auth",
                table: "member_authentication_challenges",
                columns: new[] { "ScopeId", "TokenHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_multi_factor_failure_attempts_FailedAtUtc",
                schema: "auth",
                table: "member_multi_factor_failure_attempts",
                column: "FailedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_multi_factor_failure_attempts_MemberId",
                schema: "auth",
                table: "member_multi_factor_failure_attempts",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_member_multi_factor_failure_attempts_ScopeId_MemberId_Purpo~",
                schema: "auth",
                table: "member_multi_factor_failure_attempts",
                columns: new[] { "ScopeId", "MemberId", "Purpose", "FailedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_authenticators_ActivatedAtUtc",
                schema: "auth",
                table: "member_totp_authenticators",
                column: "ActivatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_authenticators_DisabledAtUtc",
                schema: "auth",
                table: "member_totp_authenticators",
                column: "DisabledAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_authenticators_EnrollmentExpiresAtUtc",
                schema: "auth",
                table: "member_totp_authenticators",
                column: "EnrollmentExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_authenticators_MemberId",
                schema: "auth",
                table: "member_totp_authenticators",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_authenticators_ScopeId_MemberId",
                schema: "auth",
                table: "member_totp_authenticators",
                columns: new[] { "ScopeId", "MemberId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_recovery_codes_AuthenticatorId",
                schema: "auth",
                table: "member_totp_recovery_codes",
                column: "AuthenticatorId");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_recovery_codes_RevokedAtUtc",
                schema: "auth",
                table: "member_totp_recovery_codes",
                column: "RevokedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_recovery_codes_ScopeId_Hash",
                schema: "auth",
                table: "member_totp_recovery_codes",
                columns: new[] { "ScopeId", "Hash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_totp_recovery_codes_ScopeId_MemberId_ConsumedAtUtc",
                schema: "auth",
                table: "member_totp_recovery_codes",
                columns: new[] { "ScopeId", "MemberId", "ConsumedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "member_authentication_challenges",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "member_multi_factor_failure_attempts",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "member_totp_recovery_codes",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "member_totp_authenticators",
                schema: "auth");
        }
    }
}
