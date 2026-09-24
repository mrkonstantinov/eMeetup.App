using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class UserProfile
{
    // === ОСНОВНАЯ ИНФОРМАЦИЯ ===

    [JsonPropertyName("avatarUrl")]
    public string? AvatarUrl { get; set; }

    [JsonPropertyName("dateOfBirth")]
    public DateTime? DateOfBirth { get; set; }

    [JsonPropertyName("age")]
    public int Age { get; set; }

    [JsonPropertyName("bio")]
    public string? Bio { get; set; }

    // === КОНТАКТЫ ===

    [JsonPropertyName("phone")]
    public string? Phone { get; set; }

    [JsonPropertyName("telegram")]
    public string? Telegram { get; set; }

    [JsonPropertyName("instagram")]
    public string? Instagram { get; set; }

    // === ЛОКАЦИЯ ===

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

    // === СОЦИАЛЬНОЕ ===

    [JsonPropertyName("gender")]
    public string? Gender { get; set; }

    [JsonPropertyName("languages")]
    public List<string> Languages { get; set; } = new();

    [JsonPropertyName("interests")]
    public List<string> Interests { get; set; } = new();

    // === ПРЕДПОЧТЕНИЯ ===

    [JsonPropertyName("activityPreferences")]
    public ActivityPreferences ActivityPreferences { get; set; } = new();

    [JsonPropertyName("availabilityStatus")]
    public AvailabilityStatusInfo AvailabilityStatus { get; set; } = new();

    // === НАСТРОЙКИ ===

    [JsonPropertyName("isPublic")]
    public bool IsPublic { get; set; } = true;

    [JsonPropertyName("isEmailVerified")]
    public bool IsEmailVerified { get; set; }

    [JsonPropertyName("isPhoneVerified")]
    public bool IsPhoneVerified { get; set; }

    // === ФОТО ===

    [JsonPropertyName("photos")]
    public List<UserPhoto> Photos { get; set; } = new();

    [JsonPropertyName("profileImageUrl")]
    public string? ProfileImageUrl { get; set; }

    // === HELPERS ===

    public bool IsComplete()
    {
        return !string.IsNullOrEmpty(Bio)
            && DateOfBirth.HasValue
            && !string.IsNullOrEmpty(City);
    }
}
