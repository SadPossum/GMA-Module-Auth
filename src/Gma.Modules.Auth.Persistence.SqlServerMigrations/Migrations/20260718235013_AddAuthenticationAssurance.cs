using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.SqlServerMigrations.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthenticationAssurance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AuthenticatedAtUtc",
                schema: "auth",
                table: "member_sessions",
                type: "datetimeoffset",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationContextReference",
                schema: "auth",
                table: "member_sessions",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "urn:gma:acr:legacy");

            migrationBuilder.AddColumn<string>(
                name: "authentication_method_references",
                schema: "auth",
                table: "member_sessions",
                type: "nvarchar(2048)",
                maxLength: 2048,
                nullable: false,
                defaultValue: "[]");

            migrationBuilder.Sql(
                """
                UPDATE [auth].[member_sessions]
                SET [AuthenticatedAtUtc] = [LoginDateTimeUtc],
                    [AuthenticationContextReference] = CASE
                        WHEN [AuthenticationMethod] = 'password' THEN 'urn:gma:acr:password'
                        WHEN [AuthenticationMethod] LIKE 'external:%' THEN 'urn:gma:acr:external'
                        ELSE 'urn:gma:acr:legacy'
                    END,
                    [authentication_method_references] = CASE
                        WHEN [AuthenticationMethod] = 'password' THEN '["pwd"]'
                        ELSE '[]'
                    END;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AuthenticatedAtUtc",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "AuthenticationContextReference",
                schema: "auth",
                table: "member_sessions");

            migrationBuilder.DropColumn(
                name: "authentication_method_references",
                schema: "auth",
                table: "member_sessions");
        }
    }
}
