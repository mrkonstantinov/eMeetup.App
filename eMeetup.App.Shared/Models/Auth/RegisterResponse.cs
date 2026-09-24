using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Auth;

public class RegisterResponse
{
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("requiresProfileCompletion")]
    public bool RequiresProfileCompletion { get; set; }
}