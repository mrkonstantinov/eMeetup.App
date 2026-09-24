using System.Text.Json.Serialization;

namespace eMeetup.App.Shared.Models.Auth;

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; set; }

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

    [JsonPropertyName("session_state")]
    public string SessionState { get; set; } = string.Empty;

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    public DateTime ExpiresAt => DateTime.UtcNow.AddSeconds(ExpiresIn);
}