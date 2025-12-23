using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using System.Collections.Concurrent;
using eMeetup.App.Models;

public class KeycloakDummyAuthStateProvider : AuthenticationStateProvider
{
    private AuthenticationState _authenticatedState;
    private AuthenticationState _unauthenticatedState;
    private bool _isAuthenticated = false;

    private static readonly ConcurrentDictionary<string, DummyUser> _registeredUsers =
        new ConcurrentDictionary<string, DummyUser>(StringComparer.OrdinalIgnoreCase);

    public string CurrentUserName { get; set; } = string.Empty;
    public string CurrentUserEmail { get; set; } = string.Empty;
    public LoginStatus LoginStatus { get; set; } = LoginStatus.None;
    public string LoginFailureMessage { get; set; } = string.Empty;
    public RegistrationStatus RegistrationStatus { get; set; } = RegistrationStatus.None;
    public string RegistrationMessage { get; set; } = string.Empty;

    static KeycloakDummyAuthStateProvider()
    {
        _registeredUsers.TryAdd("admin@example.com", new DummyUser
        {
            Email = "admin@example.com",
            Username = "admin",
            PasswordHash = HashPassword("admin123"),
            Roles = new[] { "User", "Administrator" }
        });

        _registeredUsers.TryAdd("user@example.com", new DummyUser
        {
            Email = "user@example.com",
            Username = "user",
            PasswordHash = HashPassword("user123"),
            Roles = new[] { "User" }
        });
    }

    public KeycloakDummyAuthStateProvider()
    {
        _unauthenticatedState = new AuthenticationState(new ClaimsPrincipal());
        _authenticatedState = _unauthenticatedState;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return Task.FromResult(_isAuthenticated ? _authenticatedState : _unauthenticatedState);
    }

    public async Task<RegistrationStatus> RegisterAsync(RegistrationRequest registerRequest)
    {
        await Task.Delay(300);
        RegistrationStatus = RegistrationStatus.None;
        RegistrationMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(registerRequest?.Email) ||
            string.IsNullOrWhiteSpace(registerRequest?.Password))
        {
            RegistrationMessage = "Email and password are required.";
            RegistrationStatus = RegistrationStatus.Failed;
            return RegistrationStatus;
        }

        if (!IsValidEmail(registerRequest.Email))
        {
            RegistrationMessage = "Please enter a valid email address.";
            RegistrationStatus = RegistrationStatus.Failed;
            return RegistrationStatus;
        }

        if (registerRequest.Password.Length < 6)
        {
            RegistrationMessage = "Password must be at least 6 characters.";
            RegistrationStatus = RegistrationStatus.Failed;
            return RegistrationStatus;
        }

        if (registerRequest.Password != registerRequest.ConfirmPassword)
        {
            RegistrationMessage = "Passwords do not match.";
            RegistrationStatus = RegistrationStatus.Failed;
            return RegistrationStatus;
        }

        if (_registeredUsers.ContainsKey(registerRequest.Email))
        {
            RegistrationMessage = $"An account with email '{registerRequest.Email}' already exists.";
            RegistrationStatus = RegistrationStatus.Failed;
            return RegistrationStatus;
        }

        var username = string.IsNullOrWhiteSpace(registerRequest.Username)
            ? registerRequest.Email.Split('@')[0]
            : registerRequest.Username;

        var newUser = new DummyUser
        {
            Email = registerRequest.Email,
            Username = username,
            PasswordHash = HashPassword(registerRequest.Password),
            Roles = new[] { "User" }
        };

        if (_registeredUsers.TryAdd(registerRequest.Email, newUser))
        {
            RegistrationMessage = "Registration successful! You can now login.";
            RegistrationStatus = RegistrationStatus.Success;
        }
        else
        {
            RegistrationMessage = "Registration failed. Please try again.";
            RegistrationStatus = RegistrationStatus.Failed;
        }

        return RegistrationStatus;
    }

    public async Task<LoginStatus> LogInAsync(LoginRequest loginRequest)
    {
        await Task.Delay(300);
        LoginStatus = LoginStatus.None;
        LoginFailureMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(loginRequest?.Email) || string.IsNullOrWhiteSpace(loginRequest?.Password))
        {
            LoginFailureMessage = "Email and password are required.";
            LoginStatus = LoginStatus.Failed;
            return LoginStatus;
        }

        if (_registeredUsers.TryGetValue(loginRequest.Email, out var user))
        {
            if (VerifyPassword(loginRequest.Password, user.PasswordHash))
            {
                // ✅ This now works because Login is public
                Login(user.Username, user.Roles, user.Email);
                LoginStatus = LoginStatus.Success;
                return LoginStatus;
            }
        }

        if (loginRequest.Email == "admin@example.com" && loginRequest.Password == "admin123")
        {
            // ✅ This now works because Login is public
            Login("admin", new[] { "User", "Administrator" }, "admin@example.com");
            LoginStatus = LoginStatus.Success;
            return LoginStatus;
        }

        LoginFailureMessage = "Invalid email or password.";
        LoginStatus = LoginStatus.Failed;
        return LoginStatus;
    }

    public Task Logout()
    {
        _isAuthenticated = false;
        CurrentUserName = string.Empty;
        CurrentUserEmail = string.Empty;
        LoginStatus = LoginStatus.None;
        LoginFailureMessage = string.Empty;
        RegistrationStatus = RegistrationStatus.None;
        RegistrationMessage = string.Empty;

        // ✅ This notifies UI to show "Log In" again
        NotifyAuthenticationStateChanged(Task.FromResult(_unauthenticatedState));
        return Task.CompletedTask;
    }

    // ✅ CHANGED FROM PRIVATE TO PUBLIC
    public void Login(string username, string[] roles, string email = "")
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim("preferred_username", username),
            new Claim(ClaimTypes.Email, email ?? $"{username}@example.com"),
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var identity = new ClaimsIdentity(claims, "Dummy Keycloak Authentication");
        var user = new ClaimsPrincipal(identity);
        _authenticatedState = new AuthenticationState(user);
        _isAuthenticated = true;
        CurrentUserName = username;
        CurrentUserEmail = email ?? $"{username}@example.com";

        // ✅ This notifies UI to show "Log Out"
        NotifyAuthenticationStateChanged(Task.FromResult(_authenticatedState));
    }

    private static string HashPassword(string password)
    {
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(password + "dummy_salt"));
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var hashedInput = HashPassword(password);
        return hashedInput == storedHash;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    private class DummyUser
    {
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string[] Roles { get; set; } = Array.Empty<string>();
    }
}