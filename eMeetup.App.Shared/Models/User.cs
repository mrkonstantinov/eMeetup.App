using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class User
{
    // === ОСНОВНЫЕ ПОЛЯ (из API) ===

    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("userName")]
    public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("nickname")]
    public string Nickname { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "Inactive";

    [JsonPropertyName("profileCompleted")]
    public bool ProfileCompleted { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName("lastActiveAt")]
    public DateTime? LastActiveAt { get; set; }

    [JsonPropertyName("profile")]
    public UserProfile Profile { get; set; } = new();

    // === ДОПОЛНИТЕЛЬНЫЕ (локальные, для клиента) ===

    [JsonPropertyName("identityId")]
    public Guid? IdentityId { get; set; } // Keycloak ID

    [JsonPropertyName("updatedAt")]
    public DateTime? UpdatedAt { get; set; }

    // === HELPER PROPERTIES (не сериализуются) ===

    [JsonIgnore]
    public string DisplayName => !string.IsNullOrEmpty(Nickname) ? Nickname : UserName;

    [JsonIgnore]
    public string? ProfileImageUrl => Profile.AvatarUrl ?? Profile.ProfileImageUrl;

    [JsonIgnore]
    public int Age => Profile.Age > 0
        ? Profile.Age
        : (Profile.DateOfBirth.HasValue
            ? DateTime.Today.Year - Profile.DateOfBirth.Value.Year -
              (Profile.DateOfBirth.Value.Date > DateTime.Today.AddYears(-(DateTime.Today.Year - Profile.DateOfBirth.Value.Year)) ? 1 : 0)
            : 0);

    // === STATUS HELPERS ===

    [JsonIgnore]
    public bool IsActive => Status.Equals("Active", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsInactive => Status.Equals("Inactive", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsSuspended => Status.Equals("Suspended", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsDeleted => Status.Equals("Deleted", StringComparison.OrdinalIgnoreCase);

    public bool CanParticipate() => IsActive;

    public bool IsProfileComplete() => ProfileCompleted && Profile.IsComplete();
}

public enum UserStatus
{
    Inactive = 0,
    Active = 1,
    Suspended = 2,
    Deleted = 3
}
