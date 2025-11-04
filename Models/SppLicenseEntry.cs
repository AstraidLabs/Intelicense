using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Intelicense.Models;

public sealed class SppLicenseEntry
{
    public string? Name { get; set; }

    public string? Description { get; set; }

    public Guid ActivationId { get; set; }

    public string? ProductKeyChannel { get; set; }

    public string? PartialProductKey { get; set; }

    public string? ExtendedProductId { get; set; }

    public string? ProductId { get; set; }

    public string? OfflineInstallationId { get; set; }

    public string? LicenseStatus { get; set; }

    public string? LicenseMessage { get; set; }

    public int? LicenseStatusCode { get; set; }

    public int? NormalizedStatusCode { get; set; }

    public int? ReasonHResult { get; set; }

    public uint? GraceTimeMinutes { get; set; }

    public uint? GraceTimeDays { get; set; }

    public DateTimeOffset? GraceExpiry { get; set; }

    public DateTimeOffset? EvaluationExpiryUtc { get; set; }

    public bool? PhoneActivationAvailable { get; set; }

    public bool IsAddon { get; set; }

    public List<string> Notes { get; set; } = new();

    [JsonIgnore]
    public bool ContainsSensitiveData =>
        !string.IsNullOrWhiteSpace(ExtendedProductId) ||
        !string.IsNullOrWhiteSpace(ProductId) ||
        !string.IsNullOrWhiteSpace(OfflineInstallationId);
}
