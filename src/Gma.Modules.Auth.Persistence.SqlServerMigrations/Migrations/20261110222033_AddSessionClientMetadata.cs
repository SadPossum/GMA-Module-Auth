using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.SqlServerMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionClientMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastActivityAtUtc",
                schema: "auth",
                table: "member_sessions",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                schema: "auth",
                table: "member_sessions",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastActivityAtUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "UserAgent",
                schema: "auth",
                table: "member_sessions");
        }
    }
}
