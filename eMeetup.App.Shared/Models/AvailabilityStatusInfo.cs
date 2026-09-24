using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class AvailabilityStatusInfo
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "Available";

    [JsonPropertyName("availableFrom")]
    public DateTime? AvailableFrom { get; set; }

    [JsonPropertyName("availableUntil")]
    public DateTime? AvailableUntil { get; set; }

    [JsonPropertyName("statusMessage")]
    public string? StatusMessage { get; set; }
}