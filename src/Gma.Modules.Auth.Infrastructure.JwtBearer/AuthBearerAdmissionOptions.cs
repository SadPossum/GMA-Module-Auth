namespace Gma.Modules.Auth.Infrastructure.JwtBearer;

public sealed class AuthBearerAdmissionOptions
{
    public const string SectionName = "Auth:BearerAdmission";

    public AuthBearerAdmissionMode Mode { get; set; } = AuthBearerAdmissionMode.TokenLifetime;
}
