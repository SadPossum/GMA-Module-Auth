namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Contracts;

public sealed record MultiFactorRecoveryCodeRegenerationCompletion
{
    private MultiFactorRecoveryCodeRegenerationCompletion(
        bool succeeded,
        bool refreshTokenReuseDetected,
        MultiFactorRecoveryCodesResponse? response)
    {
        this.Succeeded = succeeded;
        this.RefreshTokenReuseDetected = refreshTokenReuseDetected;
        this.Response = response;
    }

    public static MultiFactorRecoveryCodeRegenerationCompletion Invalid { get; } = new(false, false, null);
    public static MultiFactorRecoveryCodeRegenerationCompletion ReuseDetected { get; } = new(false, true, null);

    public bool Succeeded { get; }
    public bool RefreshTokenReuseDetected { get; }
    public MultiFactorRecoveryCodesResponse? Response { get; }

    public static MultiFactorRecoveryCodeRegenerationCompletion Completed(
        MultiFactorRecoveryCodesResponse response) =>
        new(true, false, response ?? throw new ArgumentNullException(nameof(response)));
}

public sealed record MultiFactorDisableCompletion
{
    private MultiFactorDisableCompletion(bool succeeded, bool refreshTokenReuseDetected)
    {
        this.Succeeded = succeeded;
        this.RefreshTokenReuseDetected = refreshTokenReuseDetected;
    }

    public static MultiFactorDisableCompletion Invalid { get; } = new(false, false);
    public static MultiFactorDisableCompletion ReuseDetected { get; } = new(false, true);
    public static MultiFactorDisableCompletion Completed { get; } = new(true, false);

    public bool Succeeded { get; }
    public bool RefreshTokenReuseDetected { get; }
}
