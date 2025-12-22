using System.Text.Json.Serialization;

namespace eMeetup.App.Models;

public class LoginResponse
{
    [JsonPropertyName("tokenType")]
    public required string TokenType { get; set; }

    [JsonPropertyName("accessToken")]
    public required string AccessToken { get; set; }

    [JsonPropertyName("expiresIn")]
    public required int ExpiresIn { get; set; } = 0;

    [JsonPropertyName("refreshToken")]
    public required string RefreshToken { get; set; }
}
