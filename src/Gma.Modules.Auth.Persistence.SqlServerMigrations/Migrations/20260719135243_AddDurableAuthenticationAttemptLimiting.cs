using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.SqlServerMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddDurableAuthenticationAttemptLimiting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authentication_failure_attempts",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScopeId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TargetHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    FailedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authentication_failure_attempts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_authentication_failure_attempts_FailedAtUtc",
                schema: "auth",
                table: "authentication_failure_attempts",
                column: "FailedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_authentication_failure_attempts_ScopeId_Purpose_TargetHash_FailedAtUtc",
                schema: "auth",
                table: "authentication_failure_attempts",
                columns: new[] { "ScopeId", "Purpose", "TargetHash", "FailedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authentication_failure_attempts",
                schema: "auth");
        }
    }
}
