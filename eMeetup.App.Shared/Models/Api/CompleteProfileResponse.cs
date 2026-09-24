using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Api;

public class CompleteProfileResponse
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}