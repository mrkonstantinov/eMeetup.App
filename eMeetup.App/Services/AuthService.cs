using eMeetup.App.Shared.Configuration;
using eMeetup.App.Shared.Models;
using eMeetup.App.Shared.Models.Api;
using eMeetup.App.Shared.Models.Auth;
using eMeetup.App.Shared.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Maui.Storage;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace eMeetup.App.Services;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakSettings _settings;
    private readonly ILogger<AuthService> _logger;

    private const string ACCESS_TOKEN_KEY = "access_token";
    private const string REFRESH_TOKEN_KEY = "refresh_token";
    private const string ID_TOKEN_KEY = "id_token";
    private const string TOKEN_EXPIRES_KEY = "token_expires_at";
    private const string USER_KEY = "current_user";
    private const string PROFILE_COMPLETED_KEY = "profile_completed";

    public event EventHandler? AuthStateChanged;

    public AuthService(
        HttpClient httpClient,
        IOptions<KeycloakSettings> settings,
        ILogger<AuthService> logger)
    {
        _httpClient = httpClient;
        _settings = settings.Value;
        _logger = logger;
    }

    #region Login

    public async Task<AuthResult> LoginAsync(LoginRequest request)
    {
        try
        {
            _logger.LogInformation("Login attempt: {Username}", request.Username);

            var tokenRequest = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "client_id", _settings.ClientId },
                { "username", request.Username },
                { "password", request.Password },
                { "scope", "openid email profile" }
            };

            if (!string.IsNullOrEmpty(_settings.ClientSecret))
                tokenRequest.Add("client_secret", _settings.ClientSecret);

            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(_settings.TokenEndpoint, content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                return new AuthResult { Success = false, Error = ParseError(errorContent) };
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
            if (tokenResponse == null)
                return new AuthResult { Success = false, Error = "Не удалось получить токен" };

            await SaveTokensAsync(tokenResponse);

            // Загружаем профиль через API
            var user = await GetProfileAsync();

            if (user != null)
            {
                await SaveUserAsync(user, request.RememberMe);
                Preferences.Set(PROFILE_COMPLETED_KEY, user.ProfileCompleted);
            }

            AuthStateChanged?.Invoke(this, EventArgs.Empty);

            return new AuthResult { Success = true, Tokens = tokenResponse, User = user };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            return new AuthResult { Success = false, Error = $"Ошибка входа: {ex.Message}" };
        }
    }

    #endregion

    #region Register

    public async Task<AuthResult> RegisterAsync(RegisterRequest request)
    {
        try
        {
            var registerUrl = $"{_settings.ApiBaseUrl}/users/register";
            var content = new StringContent(
                JsonSerializer.Serialize(request),
                Encoding.UTF8,
                "application/json");

            var response = await _httpClient.PostAsync(registerUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                return new AuthResult { Success = false, Error = ParseError(errorContent) };
            }

            var registerResponse = await response.Content.ReadFromJsonAsync<RegisterResponse>();

            // Автоматический вход
            var loginResult = await LoginAsync(new LoginRequest
            {
                Username = request.UserName,
                Password = request.Password,
                RememberMe = true
            });

            if (loginResult.Success && registerResponse != null)
            {
                Preferences.Set(PROFILE_COMPLETED_KEY, !registerResponse.RequiresProfileCompletion);

                if (loginResult.User != null)
                {
                    loginResult.User.ProfileCompleted = !registerResponse.RequiresProfileCompletion;
                    await SaveUserAsync(loginResult.User, true);
                }
            }

            return loginResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Register error");
            return new AuthResult { Success = false, Error = $"Ошибка регистрации: {ex.Message}" };
        }
    }

    #endregion

    #region Profile

    /// <summary>
    /// GET /users/profile
    /// </summary>
    public async Task<User?> GetProfileAsync()
    {
        try
        {
            var token = await GetAccessTokenAsync();
            if (string.IsNullOrEmpty(token))
                return null;

            var url = $"{_settings.ApiBaseUrl}/users/profile";

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetProfile failed: {Status}", response.StatusCode);
                return null;
            }

            var user = await response.Content.ReadFromJsonAsync<User>();

            if (user != null)
            {
                // Обновляем флаг завершённости
                Preferences.Set(PROFILE_COMPLETED_KEY, user.ProfileCompleted);
                await SaveUserAsync(user, true);
            }

            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetProfile error");
            return null;
        }
    }

    /// <summary>
    /// POST /users/profile/complete
    /// </summary>
    public async Task<bool> CompleteProfileAsync(CompleteProfileRequest request)
    {
        try
        {
            var token = await GetAccessTokenAsync();
            if (string.IsNullOrEmpty(token))
                return false;

            var url = $"{_settings.ApiBaseUrl}/users/profile/complete";

            var httpRequest = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(request)
            };
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(httpRequest);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("CompleteProfile failed: {Error}", error);
                return false;
            }

            var completeResponse = await response.Content.ReadFromJsonAsync<CompleteProfileResponse>();
            _logger.LogInformation("Profile completed: {Message}", completeResponse?.Message);

            // Обновляем локальное состояние
            Preferences.Set(PROFILE_COMPLETED_KEY, true);

            // Перезагружаем полный профиль из API
            var updatedUser = await GetProfileAsync();

            AuthStateChanged?.Invoke(this, EventArgs.Empty);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CompleteProfile error");
            return false;
        }
    }

    public async Task<bool> RequiresProfileCompletionAsync()
    {
        // Сначала проверяем локальное хранилище
        if (Preferences.ContainsKey(PROFILE_COMPLETED_KEY))
        {
            var completed = Preferences.Get(PROFILE_COMPLETED_KEY, false);
            if (completed) return false;
        }

        // Затем проверяем через API
        var user = await GetProfileAsync();
        if (user != null)
        {
            Preferences.Set(PROFILE_COMPLETED_KEY, user.ProfileCompleted);
            return !user.ProfileCompleted;
        }

        return true; // По умолчанию требуем заполнения
    }

    #endregion

    #region Refresh / Logout

    public async Task<AuthResult> RefreshTokenAsync()
    {
        try
        {
            var refreshToken = await SecureStorage.GetAsync(REFRESH_TOKEN_KEY);
            if (string.IsNullOrEmpty(refreshToken))
                return new AuthResult { Success = false, Error = "Нет refresh токена" };

            var tokenRequest = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "client_id", _settings.ClientId },
                { "refresh_token", refreshToken }
            };

            if (!string.IsNullOrEmpty(_settings.ClientSecret))
                tokenRequest.Add("client_secret", _settings.ClientSecret);

            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(_settings.TokenEndpoint, content);

            if (!response.IsSuccessStatusCode)
            {
                await LogoutAsync();
                return new AuthResult { Success = false, Error = "Сессия истекла" };
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
            if (tokenResponse == null)
                return new AuthResult { Success = false, Error = "Ошибка обновления" };

            await SaveTokensAsync(tokenResponse);
            var user = await GetCurrentUserAsync();

            return new AuthResult { Success = true, Tokens = tokenResponse, User = user };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RefreshToken error");
            return new AuthResult { Success = false, Error = ex.Message };
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            var idToken = await SecureStorage.GetAsync(ID_TOKEN_KEY);
            if (!string.IsNullOrEmpty(idToken))
            {
                var logoutRequest = new Dictionary<string, string>
                {
                    { "client_id", _settings.ClientId },
                    { "id_token_hint", idToken }
                };
                var content = new FormUrlEncodedContent(logoutRequest);
                await _httpClient.PostAsync(_settings.LogoutEndpoint, content);
            }
        }
        catch { }

        SecureStorage.Remove(ACCESS_TOKEN_KEY);
        SecureStorage.Remove(REFRESH_TOKEN_KEY);
        SecureStorage.Remove(ID_TOKEN_KEY);
        SecureStorage.Remove(TOKEN_EXPIRES_KEY);
        SecureStorage.Remove(USER_KEY);
        Preferences.Remove(USER_KEY);
        Preferences.Remove(PROFILE_COMPLETED_KEY);

        AuthStateChanged?.Invoke(this, EventArgs.Empty);
        await Task.CompletedTask;
    }

    #endregion

    #region User Info

    public async Task<User?> GetCurrentUserAsync()
    {
        try
        {
            var userJson = await SecureStorage.GetAsync(USER_KEY);
            if (string.IsNullOrEmpty(userJson))
                userJson = Preferences.Get(USER_KEY, string.Empty);

            if (string.IsNullOrEmpty(userJson))
                return null;

            return JsonSerializer.Deserialize<User>(userJson);
        }
        catch
        {
            return null;
        }
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        var token = await GetAccessTokenAsync();
        if (string.IsNullOrEmpty(token)) return false;

        var expiresAtStr = await SecureStorage.GetAsync(TOKEN_EXPIRES_KEY);
        if (DateTime.TryParse(expiresAtStr, out var expiresAt))
        {
            if (expiresAt <= DateTime.UtcNow.AddMinutes(-1))
            {
                var refreshResult = await RefreshTokenAsync();
                return refreshResult.Success;
            }
        }
        return true;
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        try
        {
            return await SecureStorage.GetAsync(ACCESS_TOKEN_KEY);
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region Helpers

    private async Task SaveTokensAsync(TokenResponse tokens)
    {
        await SecureStorage.SetAsync(ACCESS_TOKEN_KEY, tokens.AccessToken);
        await SecureStorage.SetAsync(REFRESH_TOKEN_KEY, tokens.RefreshToken);
        await SecureStorage.SetAsync(ID_TOKEN_KEY, tokens.IdToken);
        await SecureStorage.SetAsync(TOKEN_EXPIRES_KEY, tokens.ExpiresAt.ToString("O"));
    }

    private async Task SaveUserAsync(User user, bool rememberMe)
    {
        var json = JsonSerializer.Serialize(user);
        await SecureStorage.SetAsync(USER_KEY, json);
        if (rememberMe)
            Preferences.Set(USER_KEY, json);
    }

    private string ParseError(string errorJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(errorJson);
            var root = doc.RootElement;

            if (root.TryGetProperty("error_description", out var desc))
                return desc.GetString() ?? "Ошибка";
            if (root.TryGetProperty("error", out var err))
                return err.GetString() ?? "Ошибка";
            if (root.TryGetProperty("message", out var msg))
                return msg.GetString() ?? "Ошибка";
            if (root.TryGetProperty("title", out var title))
                return title.GetString() ?? "Ошибка";
        }
        catch { }
        return errorJson;
    }

    #endregion
}