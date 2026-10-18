using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gma.Modules.Auth.Persistence.SqlServerMigrations.Migrations;

public partial class ReserveUnknownRememberedBrowserValues : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("UPDATE [auth].[remembered_browser_devices] SET [State] = [State] + 1 WHERE [State] BETWEEN 0 AND 5;");
        migrationBuilder.Sql("UPDATE [auth].[remembered_browser_operations] SET [Outcome] = [Outcome] + 1 WHERE [Outcome] BETWEEN 0 AND 7;");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("UPDATE [auth].[remembered_browser_devices] SET [State] = [State] - 1 WHERE [State] BETWEEN 1 AND 6;");
        migrationBuilder.Sql("UPDATE [auth].[remembered_browser_operations] SET [Outcome] = [Outcome] - 1 WHERE [Outcome] BETWEEN 1 AND 8;");
    }
}
