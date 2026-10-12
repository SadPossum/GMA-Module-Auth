using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.PostgreSqlMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddRememberedBrowserAccountSwitching : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "SecurityEpoch",
                schema: "auth",
                table: "members",
                type: "bigint",
                nullable: false,
                defaultValue: 1L);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RememberedAbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RememberedAccountProofId",
                schema: "auth",
                table: "member_sessions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RememberedBrowserDeviceId",
                schema: "auth",
                table: "member_sessions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "RememberedBrowserGeneration",
                schema: "auth",
                table: "member_sessions",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "RememberedSecurityEpoch",
                schema: "auth",
                table: "member_sessions",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RememberedBrowserDeviceId",
                schema: "auth",
                table: "member_authentication_challenges",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "RememberedBrowserGeneration",
                schema: "auth",
                table: "member_authentication_challenges",
                type: "bigint",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "remembered_browser_devices",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CredentialHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RestoreEpoch = table.Column<long>(type: "bigint", nullable: false),
                    Generation = table.Column<long>(type: "bigint", nullable: false),
                    ConcurrencyStamp = table.Column<Guid>(type: "uuid", nullable: false),
                    State = table.Column<int>(type: "integer", nullable: false),
                    PinDigits = table.Column<int>(type: "integer", nullable: false),
                    ActiveMemberId = table.Column<Guid>(type: "uuid", nullable: true),
                    ActiveSessionId = table.Column<Guid>(type: "uuid", nullable: true),
                    ActiveProofId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IdleExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remembered_browser_devices", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "remembered_account_proofs",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    OriginalSessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    PinHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    PepperVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Label = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    AuthenticatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RevokedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remembered_account_proofs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remembered_account_proofs_remembered_browser_devices_Device~",
                        column: x => x.DeviceId,
                        principalSchema: "auth",
                        principalTable: "remembered_browser_devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "remembered_browser_operations",
                schema: "auth",
                columns: table => new
                {
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    OperationId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    ExpectedGeneration = table.Column<long>(type: "bigint", nullable: false),
                    ResultGeneration = table.Column<long>(type: "bigint", nullable: false),
                    ProofId = table.Column<Guid>(type: "uuid", nullable: true),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: true),
                    SessionId = table.Column<Guid>(type: "uuid", nullable: true),
                    Outcome = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remembered_browser_operations", x => new { x.DeviceId, x.OperationId });
                    table.ForeignKey(
                        name: "FK_remembered_browser_operations_remembered_browser_devices_De~",
                        column: x => x.DeviceId,
                        principalSchema: "auth",
                        principalTable: "remembered_browser_devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_remembered_account_proofs_DeviceId_MemberId",
                schema: "auth",
                table: "remembered_account_proofs",
                columns: new[] { "DeviceId", "MemberId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_remembered_account_proofs_ExpiresAtUtc",
                schema: "auth",
                table: "remembered_account_proofs",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remembered_account_proofs_ScopeId_MemberId",
                schema: "auth",
                table: "remembered_account_proofs",
                columns: new[] { "ScopeId", "MemberId" });

            migrationBuilder.CreateIndex(
                name: "IX_remembered_browser_devices_CredentialHash",
                schema: "auth",
                table: "remembered_browser_devices",
                column: "CredentialHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_remembered_browser_devices_ExpiresAtUtc",
                schema: "auth",
                table: "remembered_browser_devices",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remembered_browser_operations_ScopeId_MemberId",
                schema: "auth",
                table: "remembered_browser_operations",
                columns: new[] { "ScopeId", "MemberId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "remembered_account_proofs",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "remembered_browser_operations",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "remembered_browser_devices",
                schema: "auth");

            migrationBuilder.DropColumn(
                name: "SecurityEpoch",
                schema: "auth",
                table: "members");

            migrationBuilder.DropColumn(
                name: "RememberedAbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "RememberedAccountProofId",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "RememberedBrowserDeviceId",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "RememberedBrowserGeneration",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "RememberedSecurityEpoch",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "RememberedBrowserDeviceId",
                schema: "auth",
                table: "member_authentication_challenges");

            migrationBuilder.DropColumn(
                name: "RememberedBrowserGeneration",
                schema: "auth",
                table: "member_authentication_challenges");
        }
    }
}
