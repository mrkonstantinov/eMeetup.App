namespace eMeetup.App.Shared.Configuration;

public class KeycloakSettings
{
    public string Authority { get; set; } = "https://localhost:6001/realms/emeetup";
    public string TokenEndpoint { get; set; } = "https://localhost:6001/realms/emeetup/protocol/openid-connect/token";
    public string LogoutEndpoint { get; set; } = "https://localhost:6001/realms/emeetup/protocol/openid-connect/logout";
    public string ClientId { get; set; } = "emeetup-public-client";
    public string ClientSecret { get; set; } = string.Empty;
    public string ApiBaseUrl { get; set; } = "http://localhost:5000";
}