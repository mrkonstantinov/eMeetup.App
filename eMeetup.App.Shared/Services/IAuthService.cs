using eMeetup.App.Shared.Models;
using eMeetup.App.Shared.Models.Api;
using eMeetup.App.Shared.Models.Auth;

namespace eMeetup.App.Shared.Services;

public interface IAuthService
{
    // Аутентификация
    Task<AuthResult> LoginAsync(LoginRequest request);
    Task<AuthResult> RegisterAsync(RegisterRequest request);
    Task<AuthResult> RefreshTokenAsync();
    Task LogoutAsync();

    // Текущий пользователь
    Task<User?> GetCurrentUserAsync();
    Task<bool> IsAuthenticatedAsync();
    Task<string?> GetAccessTokenAsync();
    Task<bool> RequiresProfileCompletionAsync();

    // Профиль
    Task<User?> GetProfileAsync(); // GET /users/profile
    Task<bool> CompleteProfileAsync(CompleteProfileRequest request); // POST /users/profile/complete

    // События
    event EventHandler? AuthStateChanged;
}