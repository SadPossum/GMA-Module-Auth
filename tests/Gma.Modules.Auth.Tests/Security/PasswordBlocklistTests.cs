namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application.Security;
using Xunit;

[Trait("Category", "Unit")]
public sealed class PasswordBlocklistTests
{
    [Fact]
    public async Task Built_in_blocklist_rejects_common_password_and_allows_replacement()
    {
        CommonPasswordBlocklist blocklist = new();

        Assert.True(await blocklist.IsBlockedAsync("passwordpassword", CancellationToken.None));
        Assert.False(await blocklist.IsBlockedAsync("a deliberately uncommon passphrase", CancellationToken.None));
    }
}
