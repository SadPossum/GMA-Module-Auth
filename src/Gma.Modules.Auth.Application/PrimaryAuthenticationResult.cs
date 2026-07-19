namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Contracts;

public sealed record PrimaryAuthenticationResult
{
    private PrimaryAuthenticationResult(
        AuthTokensResponse? tokens,
        MultiFactorChallengeResponse? multiFactorChallenge)
    {
        if ((tokens is null) == (multiFactorChallenge is null))
        {
            throw new ArgumentException(
                "A primary authentication result must contain either tokens or a multi-factor challenge.");
        }

        this.Tokens = tokens;
        this.MultiFactorChallenge = multiFactorChallenge;
    }

    public AuthTokensResponse? Tokens { get; }
    public MultiFactorChallengeResponse? MultiFactorChallenge { get; }
    public bool RequiresMultiFactor => this.MultiFactorChallenge is not null;

    public static PrimaryAuthenticationResult Authenticated(AuthTokensResponse tokens) =>
        new(tokens ?? throw new ArgumentNullException(nameof(tokens)), null);

    public static PrimaryAuthenticationResult Challenge(MultiFactorChallengeResponse challenge) =>
        new(null, challenge ?? throw new ArgumentNullException(nameof(challenge)));
}
