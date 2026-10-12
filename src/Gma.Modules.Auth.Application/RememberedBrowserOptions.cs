namespace Gma.Modules.Auth.Application;

public sealed class RememberedBrowserOptions
{
    public const string SectionName = "Auth:RememberedBrowser";

    public bool Enabled { get; set; }
    public int PinDigits { get; set; } = 6;
    public int IdleMinutes { get; set; } = 5;
    public int MaximumAccounts { get; set; } = 8;
    public int FailedPinLimit { get; set; } = 5;
    public int DeviceAttemptLimit { get; set; } = 20;
    public int AttemptWindowMinutes { get; set; } = 15;
    public int MaximumConcurrentKdf { get; set; } = 2;
    public long RestoreEpoch { get; set; }
    public string PepperVersion { get; set; } = string.Empty;
    public string Pepper { get; set; } = string.Empty;

    public bool IsValid()
    {
        if (!this.Enabled)
        {
            return true;
        }

        if (this.PinDigits is < 4 or > 12 || this.IdleMinutes is < 1 or > 30 ||
            this.MaximumAccounts is < 1 or > 20 || this.FailedPinLimit is < 1 or > 5 ||
            this.DeviceAttemptLimit is < 5 or > 50 || this.AttemptWindowMinutes is < 1 or > 60 ||
            this.MaximumConcurrentKdf is < 1 or > 4 || this.RestoreEpoch <= 0 ||
            this.PepperVersion.Length is < 1 or > 64 ||
            !this.PepperVersion.All(value => char.IsAsciiLetterOrDigit(value) || value is '-' or '.'))
        {
            return false;
        }

        Span<byte> key = stackalloc byte[64];
        return Convert.TryFromBase64String(this.Pepper, key, out int written) && written >= 32;
    }
}
