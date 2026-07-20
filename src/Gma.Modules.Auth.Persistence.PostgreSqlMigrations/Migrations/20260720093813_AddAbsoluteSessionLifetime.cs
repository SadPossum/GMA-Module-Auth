using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.PostgreSqlMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddAbsoluteSessionLifetime : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE auth.member_sessions
                SET "AbsoluteExpiresAtUtc" = "RefreshTokenExpiresAtUtc";
                """);

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "AbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions",
                type: "timestamp with time zone",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "timestamp with time zone",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_member_sessions_AbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions",
                column: "AbsoluteExpiresAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_member_sessions_AbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "AbsoluteExpiresAtUtc",
                schema: "auth",
                table: "member_sessions");
        }
    }
}
