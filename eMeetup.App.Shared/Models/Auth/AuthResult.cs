namespace eMeetup.App.Shared.Models.Auth;

public class AuthResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public TokenResponse? Tokens { get; set; }
    public User? User { get; set; }
}