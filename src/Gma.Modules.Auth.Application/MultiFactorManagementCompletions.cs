namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Contracts;

public sealed record MultiFactorRecoveryCodeRegenerationCompletion
{
    private MultiFactorRecoveryCodeRegenerationCompletion(
        bool succeeded,
        MultiFactorRecoveryCodesResponse? response)
    {
        this.Succeeded = succeeded;
        this.Response = response;
    }

    public static MultiFactorRecoveryCodeRegenerationCompletion Invalid { get; } = new(false, null);

    public bool Succeeded { get; }
    public MultiFactorRecoveryCodesResponse? Response { get; }

    public static MultiFactorRecoveryCodeRegenerationCompletion Completed(
        MultiFactorRecoveryCodesResponse response) =>
        new(true, response ?? throw new ArgumentNullException(nameof(response)));
}

public sealed record MultiFactorDisableCompletion
{
    private MultiFactorDisableCompletion(bool succeeded) => this.Succeeded = succeeded;

    public static MultiFactorDisableCompletion Invalid { get; } = new(false);
    public static MultiFactorDisableCompletion Completed { get; } = new(true);

    public bool Succeeded { get; }
}
