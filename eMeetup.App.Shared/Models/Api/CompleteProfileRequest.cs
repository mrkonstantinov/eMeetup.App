using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Api;

public class CompleteProfileRequest
{
    [JsonPropertyName("avatarUrl")]
    public string? AvatarUrl { get; set; }

    [JsonPropertyName("dateOfBirth")]
    public DateTime? DateOfBirth { get; set; }

    [JsonPropertyName("bio")]
    public string? Bio { get; set; }

    [JsonPropertyName("phone")]
    public string? Phone { get; set; }

    [JsonPropertyName("telegram")]
    public string? Telegram { get; set; }

    [JsonPropertyName("instagram")]
    public string? Instagram { get; set; }

    [JsonPropertyName("city")]
    public string? City { get; set; }

    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("latitude")]
    public double? Latitude { get; set; }

    [JsonPropertyName("longitude")]
    public double? Longitude { get; set; }

    [JsonPropertyName("timeZone")]
    public string? TimeZone { get; set; }

    [JsonPropertyName("gender")]
    public string? Gender { get; set; }

    [JsonPropertyName("languages")]
    public string? Languages { get; set; }

    [JsonPropertyName("interests")]
    public string? Interests { get; set; }
}