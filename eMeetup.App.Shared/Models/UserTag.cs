using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models;

public class UserTag
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("tagGroupId")]
    public Guid? TagGroupId { get; set; }

    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; } = true;

    [JsonPropertyName("usageCount")]
    public int UsageCount { get; set; }
}