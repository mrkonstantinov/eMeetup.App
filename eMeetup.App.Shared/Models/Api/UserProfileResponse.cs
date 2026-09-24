using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Api;

public class UserProfileResponse
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("userName")]
    public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("nickname")]
    public string Nickname { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty; // Active, Inactive, Suspended, Deleted

    [JsonPropertyName("profileCompleted")]
    public bool ProfileCompleted { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName("lastActiveAt")]
    public DateTime? LastActiveAt { get; set; }

    [JsonPropertyName("profile")]
    public ProfileDto Profile { get; set; } = new();
}

public class ProfileDto
{
    [JsonPropertyName("avatarUrl")]
    public string? AvatarUrl { get; set; }

    [JsonPropertyName("dateOfBirth")]
    public DateTime? DateOfBirth { get; set; }

    [JsonPropertyName("age")]
    public int Age { get; set; }

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
    public List<string> Languages { get; set; } = new();

    [JsonPropertyName("interests")]
    public List<string> Interests { get; set; } = new();

    [JsonPropertyName("activityPreferences")]
    public ActivityPreferencesDto ActivityPreferences { get; set; } = new();

    [JsonPropertyName("availabilityStatus")]
    public AvailabilityStatusDto AvailabilityStatus { get; set; } = new();

    [JsonPropertyName("isPublic")]
    public bool IsPublic { get; set; }

    [JsonPropertyName("isEmailVerified")]
    public bool IsEmailVerified { get; set; }

    [JsonPropertyName("isPhoneVerified")]
    public bool IsPhoneVerified { get; set; }

    [JsonPropertyName("photos")]
    public List<PhotoDto> Photos { get; set; } = new();

    [JsonPropertyName("profileImageUrl")]
    public string? ProfileImageUrl { get; set; }
}

public class ActivityPreferencesDto
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

public class AvailabilityStatusDto
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

public class PhotoDto
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("isPrimary")]
    public bool IsPrimary { get; set; }

    [JsonPropertyName("displayOrder")]
    public int DisplayOrder { get; set; }
}