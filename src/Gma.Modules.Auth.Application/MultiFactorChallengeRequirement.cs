namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Contracts;

internal sealed record MultiFactorChallengeRequirement
{
    private MultiFactorChallengeRequirement(bool isRequired, MultiFactorChallengeResponse? challenge)
    {
        if (isRequired != (challenge is not null))
        {
            throw new ArgumentException("A required multi-factor challenge must include challenge details.", nameof(challenge));
        }

        this.IsRequired = isRequired;
        this.Challenge = challenge;
    }

    public static MultiFactorChallengeRequirement NotRequired { get; } = new(false, null);

    public bool IsRequired { get; }
    public MultiFactorChallengeResponse? Challenge { get; }

    public static MultiFactorChallengeRequirement Required(MultiFactorChallengeResponse challenge) =>
        new(true, challenge ?? throw new ArgumentNullException(nameof(challenge)));
}
