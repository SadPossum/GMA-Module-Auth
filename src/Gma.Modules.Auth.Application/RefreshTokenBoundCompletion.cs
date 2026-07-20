namespace Gma.Modules.Auth.Application;

public sealed record RefreshTokenBoundCompletion<TResponse>
    where TResponse : class
{
    private readonly TResponse? response;

    private RefreshTokenBoundCompletion(bool succeeded, bool refreshTokenReuseDetected, TResponse? response)
    {
        this.Succeeded = succeeded;
        this.RefreshTokenReuseDetected = refreshTokenReuseDetected;
        this.response = response;
    }

    public bool Succeeded { get; }
    public bool RefreshTokenReuseDetected { get; }
    public TResponse Response => this.Succeeded
        ? this.response!
        : throw new InvalidOperationException("The operation did not produce a response.");

    internal static RefreshTokenBoundCompletion<TResponse> Create(
        bool succeeded,
        bool refreshTokenReuseDetected,
        TResponse? response) =>
        new(succeeded, refreshTokenReuseDetected, response);
}

public static class RefreshTokenBoundCompletion
{
    public static RefreshTokenBoundCompletion<TResponse> Completed<TResponse>(TResponse response)
        where TResponse : class =>
        RefreshTokenBoundCompletion<TResponse>.Create(
            succeeded: true,
            refreshTokenReuseDetected: false,
            response ?? throw new ArgumentNullException(nameof(response)));

    public static RefreshTokenBoundCompletion<TResponse> ReuseDetected<TResponse>()
        where TResponse : class =>
        RefreshTokenBoundCompletion<TResponse>.Create(
            succeeded: false,
            refreshTokenReuseDetected: true,
            response: null);
}
