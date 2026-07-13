namespace Gma.Modules.Auth.Persistence;

public sealed class AuthRetentionOptions
{
    public const string SectionName = "Auth:Retention";

    public bool Enabled { get; set; }
    public int ExpiredExchangeHistoryHours { get; set; } = 24;
    public int SessionHistoryDays { get; set; } = 365;
    public int BatchSize { get; set; } = 500;
    public int MaxBatchesPerCategoryPerCycle { get; set; } = 4;
    public int IntervalMinutes { get; set; } = 60;
}
