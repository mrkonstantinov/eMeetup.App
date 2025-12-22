using System.Security.Claims;
using eMeetup.App.Models;
using Microsoft.AspNetCore.Components.Authorization;

public class KeycloakDummyAuthStateProvider : AuthenticationStateProvider
{
    private AuthenticationState _authenticatedState;
    private AuthenticationState _unauthenticatedState;
    private bool _isAuthenticated = false;

    // Current user info (helpful for UI)
    public string CurrentUserName { get; private set; } = string.Empty;

    public LoginStatus LoginStatus { get; private set; } = LoginStatus.None;
    public string LoginFailureMessage { get; private set; } = string.Empty;

    public KeycloakDummyAuthStateProvider()
    {
        _unauthenticatedState = new AuthenticationState(new ClaimsPrincipal());
        _authenticatedState = _unauthenticatedState;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var state = _isAuthenticated ? _authenticatedState : _unauthenticatedState;
        return Task.FromResult(state);
    }

    public async Task<LoginStatus> LogInAsync(LoginRequest loginRequest)
    {
        await Task.Delay(500);
        LoginStatus = LoginStatus.None;
        LoginFailureMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(loginRequest?.Email) || string.IsNullOrWhiteSpace(loginRequest?.Password))
        {
            LoginFailureMessage = "Email and password are required.";
            LoginStatus = LoginStatus.Failed;
            return LoginStatus;
        }

        // Your dummy login logic
        if (loginRequest.Email == "admin@example.com" && loginRequest.Password == "admin123")
        {
            Login("admin", new[] { "User", "Administrator" });
            LoginStatus = LoginStatus.Success;
            return LoginStatus;
        }

        if (loginRequest.Email.EndsWith("@example.com", StringComparison.OrdinalIgnoreCase))
        {
            var username = loginRequest.Email.Split('@')[0];
            Login(username, new[] { "User" });
            LoginStatus = LoginStatus.Success;
            return LoginStatus;
        }

        LoginFailureMessage = "Invalid email or password.";
        LoginStatus = LoginStatus.Failed;
        return LoginStatus;
    }

    // ----- NEW: The Logout Method -----
    public Task Logout()
    {
        _isAuthenticated = false;
        CurrentUserName = string.Empty;
        LoginStatus = LoginStatus.None;
        LoginFailureMessage = string.Empty;

        // Critical: This notifies all Blazor components that auth state changed
        NotifyAuthenticationStateChanged(Task.FromResult(_unauthenticatedState));

        return Task.CompletedTask;
    }

    private void Login(string username, string[] roles)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim("preferred_username", username),
            new Claim(ClaimTypes.Email, $"{username}@example.com"),
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var identity = new ClaimsIdentity(claims, "Dummy Keycloak Authentication");
        var user = new ClaimsPrincipal(identity);
        _authenticatedState = new AuthenticationState(user);
        _isAuthenticated = true;
        CurrentUserName = username; // Store username for UI

        NotifyAuthenticationStateChanged(Task.FromResult(_authenticatedState));
    }
}
