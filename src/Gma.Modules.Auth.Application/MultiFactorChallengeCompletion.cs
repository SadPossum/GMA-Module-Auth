namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Contracts;

public sealed record MultiFactorChallengeCompletion
{
    private MultiFactorChallengeCompletion(bool succeeded, AuthTokensResponse? tokens)
    {
        if (succeeded != (tokens is not null))
        {
            throw new ArgumentException(
                "A successful multi-factor challenge completion must contain tokens.",
                nameof(tokens));
        }

        this.Succeeded = succeeded;
        this.Tokens = tokens;
    }

    public static MultiFactorChallengeCompletion Invalid { get; } = new(false, null);

    public bool Succeeded { get; }
    public AuthTokensResponse? Tokens { get; }

    public static MultiFactorChallengeCompletion Authenticated(AuthTokensResponse tokens) =>
        new(true, tokens ?? throw new ArgumentNullException(nameof(tokens)));
}
