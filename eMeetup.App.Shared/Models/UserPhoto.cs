using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class UserPhoto
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("userId")]
    public Guid? UserId { get; set; }

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("isPrimary")]
    public bool IsPrimary { get; set; }

    [JsonPropertyName("displayOrder")]
    public int DisplayOrder { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTime? CreatedAt { get; set; }
}