using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class ActivityPreferences
{
    [JsonPropertyName("preferredActivities")]
    public List<string> PreferredActivities { get; set; } = new();

    [JsonPropertyName("activityLevels")]
    public List<string> ActivityLevels { get; set; } = new();

    [JsonPropertyName("preferredTimeOfDay")]
    public string? PreferredTimeOfDay { get; set; }

    [JsonPropertyName("preferredDays")]
    public List<string> PreferredDays { get; set; } = new();

    [JsonPropertyName("maxDistanceKm")]
    public int? MaxDistanceKm { get; set; }

    [JsonPropertyName("minParticipants")]
    public int? MinParticipants { get; set; }

    [JsonPropertyName("maxParticipants")]
    public int? MaxParticipants { get; set; }
}