using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Auth;

public class RegisterRequest
{
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("userName")]
    public string UserName { get; set; } = string.Empty;
}