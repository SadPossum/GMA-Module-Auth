namespace Gma.Modules.Auth.Tests.Contracts;

using Gma.Modules.Auth.Contracts;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthSubjectStatusContractTests
{
    [Fact]
    public void Snapshot_exposes_only_scope_canonical_subject_and_status()
    {
        string[] properties = typeof(AuthSubjectStatusSnapshot)
            .GetProperties()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["ScopeId", "Status", "SubjectId"], properties);
    }
}
