using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.PostgreSqlMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "password_recovery_challenges",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    RequestedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ConcurrencyStamp = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_password_recovery_challenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_password_recovery_challenges_members_MemberId",
                        column: x => x.MemberId,
                        principalSchema: "auth",
                        principalTable: "members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_ConsumedAtUtc",
                schema: "auth",
                table: "password_recovery_challenges",
                column: "ConsumedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_ExpiresAtUtc",
                schema: "auth",
                table: "password_recovery_challenges",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_MemberId",
                schema: "auth",
                table: "password_recovery_challenges",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_RevokedAtUtc",
                schema: "auth",
                table: "password_recovery_challenges",
                column: "RevokedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_ScopeId_MemberId_RequestedAtUtc",
                schema: "auth",
                table: "password_recovery_challenges",
                columns: new[] { "ScopeId", "MemberId", "RequestedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_password_recovery_challenges_ScopeId_TokenHash",
                schema: "auth",
                table: "password_recovery_challenges",
                columns: new[] { "ScopeId", "TokenHash" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "password_recovery_challenges",
                schema: "auth");
        }
    }
}
