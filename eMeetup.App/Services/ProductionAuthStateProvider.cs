using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Text.Json;
using eMeetup.App.Models;

namespace eMeetup.App.Providers
{
    public class ProductionAuthStateProvider : AuthenticationStateProvider
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<ProductionAuthStateProvider> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

        private AuthenticationState _authenticatedState;
        private AuthenticationState _unauthenticatedState;
        private bool _isAuthenticated = false;
        private bool _isInitialized = false;
        private readonly SemaphoreSlim _initializationLock = new(1, 1);

        // API Configuration
        private readonly string _apiBaseUrl = "http://localhost:5000"; // Change to your API URL
        private readonly string _tokenStorageKey = "auth_token";
        private readonly string _refreshTokenStorageKey = "refresh_token";
        private readonly string _userStorageKey = "user_data";

        // User state properties
        public string CurrentUserName { get; private set; } = string.Empty;
        public string CurrentUserEmail { get; private set; } = string.Empty;
        public Guid CurrentUserId { get; private set; } = Guid.Empty;

        // Status properties
        public LoginStatus LoginStatus { get; set; } = LoginStatus.None;
        public string LoginFailureMessage { get; set; } = string.Empty;
        public RegistrationStatus RegistrationStatus { get; set; } = RegistrationStatus.None;
        public string RegistrationMessage { get; set; } = string.Empty;

        // Image upload properties
        public byte[]? SelectedProfileImage { get; set; }
        public string? SelectedImageFileName { get; set; }
        public string? SelectedImageContentType { get; set; }

        public ProductionAuthStateProvider(HttpClient httpClient, ILogger<ProductionAuthStateProvider> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            _unauthenticatedState = new AuthenticationState(new ClaimsPrincipal());
            _authenticatedState = _unauthenticatedState;

            // Initialize synchronously - don't call async methods in constructor
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            // Ensure initialization only happens once
            if (!_isInitialized)
            {
                await _initializationLock.WaitAsync();
                try
                {
                    if (!_isInitialized)
                    {
                        await InitializeFromStorage();
                        _isInitialized = true;
                    }
                }
                finally
                {
                    _initializationLock.Release();
                }
            }

            // If already authenticated, return cached state
            if (_isAuthenticated)
                return _authenticatedState;

            return _unauthenticatedState;
        }

        // =============== IMAGE SELECTION METHODS ===============
        public async Task<bool> SelectProfileImageFromGallery()
        {
            try
            {
                var status = await Permissions.CheckStatusAsync<Permissions.Photos>();
                if (status != PermissionStatus.Granted)
                {
                    status = await Permissions.RequestAsync<Permissions.Photos>();
                }

                if (status == PermissionStatus.Granted)
                {
                    var result = await MediaPicker.PickPhotoAsync(new MediaPickerOptions
                    {
                        Title = "Select Profile Picture"
                    });

                    if (result != null)
                    {
                        await ProcessSelectedImage(result);
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error selecting image from gallery");
                throw new Exception($"Failed to select image: {ex.Message}");
            }

            return false;
        }

        public async Task<bool> TakeProfilePhoto()
        {
            try
            {
                var status = await Permissions.CheckStatusAsync<Permissions.Camera>();
                if (status != PermissionStatus.Granted)
                {
                    status = await Permissions.RequestAsync<Permissions.Camera>();
                }

                if (status == PermissionStatus.Granted)
                {
                    var result = await MediaPicker.CapturePhotoAsync();

                    if (result != null)
                    {
                        await ProcessSelectedImage(result);
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error taking photo");
                throw new Exception($"Failed to take photo: {ex.Message}");
            }

            return false;
        }

        private async Task ProcessSelectedImage(FileResult result)
        {
            try
            {
                // Validate file size (max 5MB)
                var fileInfo = new FileInfo(result.FullPath);
                if (fileInfo.Length > 5 * 1024 * 1024)
                {
                    throw new Exception("Image must be less than 5MB");
                }

                // Read file bytes
                using var stream = await result.OpenReadAsync();
                using var memoryStream = new MemoryStream();
                await stream.CopyToAsync(memoryStream);

                SelectedProfileImage = memoryStream.ToArray();
                SelectedImageFileName = result.FileName;
                SelectedImageContentType = GetContentType(result.FileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing selected image");
                throw;
            }
        }

        private string GetContentType(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            return extension switch
            {
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                ".gif" => "image/gif",
                ".bmp" => "image/bmp",
                ".webp" => "image/webp",
                _ => "application/octet-stream"
            };
        }

        public void ClearSelectedImage()
        {
            SelectedProfileImage = null;
            SelectedImageFileName = null;
            SelectedImageContentType = null;
        }

        // =============== REGISTRATION ===============
        public async Task<RegistrationStatus> RegisterAsync(RegistrationRequest registerRequest)
        {
            RegistrationStatus = RegistrationStatus.None;
            RegistrationMessage = string.Empty;

            try
            {
                // Create multipart form data
                using var formData = new MultipartFormDataContent();

                // Add basic user data as form fields
                formData.Add(new StringContent(registerRequest.Email), "Email");
                formData.Add(new StringContent(registerRequest.Password), "Password");
                formData.Add(new StringContent(registerRequest.Username), "Username");
                formData.Add(new StringContent(registerRequest.DateOfBirth.ToString("yyyy-MM-dd")), "DateOfBirth");
                formData.Add(new StringContent(((int)registerRequest.Gender).ToString()), "Gender");

                // Add optional fields if they have values
                if (!string.IsNullOrEmpty(registerRequest.Bio))
                    formData.Add(new StringContent(registerRequest.Bio), "Bio");

                if (registerRequest.Latitude.HasValue)
                    formData.Add(new StringContent(registerRequest.Latitude.Value.ToString()), "Latitude");

                if (registerRequest.Longitude.HasValue)
                    formData.Add(new StringContent(registerRequest.Longitude.Value.ToString()), "Longitude");

                if (!string.IsNullOrEmpty(registerRequest.City))
                    formData.Add(new StringContent(registerRequest.City), "City");

                if (!string.IsNullOrEmpty(registerRequest.Country))
                    formData.Add(new StringContent(registerRequest.Country), "Country");

                if (!string.IsNullOrEmpty(registerRequest.Interests))
                    formData.Add(new StringContent(registerRequest.Interests), "Interests");

                // Add profile image file if available
                if (SelectedProfileImage != null && SelectedImageFileName != null)
                {
                    var imageContent = new ByteArrayContent(SelectedProfileImage);
                    imageContent.Headers.ContentType = new MediaTypeHeaderValue(SelectedImageContentType ?? "image/jpeg");
                    formData.Add(imageContent, "Photos", SelectedImageFileName ?? "profile.jpg");
                }

                // Send registration request to API
                var response = await _httpClient.PostAsync($"{_apiBaseUrl}/users/register", formData);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var registrationResponse = JsonSerializer.Deserialize<RegistrationResponse>(responseContent, _jsonOptions);

                    if (registrationResponse?.Success == true && registrationResponse.UserId != Guid.Empty)
                    {
                        RegistrationMessage = "Registration successful!";
                        RegistrationStatus = RegistrationStatus.Success;

                        // Clear selected image after successful registration
                        ClearSelectedImage();

                        return RegistrationStatus;
                    }
                    else
                    {
                        RegistrationMessage = registrationResponse?.Message ?? "Registration failed";
                        RegistrationStatus = RegistrationStatus.Failed;
                    }
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    RegistrationMessage = $"Registration failed: {response.StatusCode}";

                    try
                    {
                        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(errorContent, _jsonOptions);
                        RegistrationMessage = errorResponse?.Message ?? RegistrationMessage;

                        // Add validation errors if available
                        if (errorResponse?.Errors != null)
                        {
                            var validationErrors = string.Join(", ", errorResponse.Errors.SelectMany(e => e.Value));
                            if (!string.IsNullOrEmpty(validationErrors))
                            {
                                RegistrationMessage += $". {validationErrors}";
                            }
                        }
                    }
                    catch
                    {
                        RegistrationMessage = await response.Content.ReadAsStringAsync();
                    }

                    RegistrationStatus = RegistrationStatus.Failed;
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Network error during registration");
                RegistrationMessage = "Network error. Please check your connection.";
                RegistrationStatus = RegistrationStatus.Failed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during registration");
                RegistrationMessage = $"Unexpected error: {ex.Message}";
                RegistrationStatus = RegistrationStatus.Failed;
            }

            return RegistrationStatus;
        }

        // =============== LOGIN ===============
        public async Task<LoginStatus> LogInAsync(LoginRequest loginRequest)
        {
            LoginStatus = LoginStatus.None;
            LoginFailureMessage = string.Empty;

            try
            {
                var loginData = new
                {
                    Email = loginRequest.Email,
                    Password = loginRequest.Password
                };

                var json = JsonSerializer.Serialize(loginData, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_apiBaseUrl}/auth/login", content);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var authResponse = JsonSerializer.Deserialize<AuthResponse>(responseContent, _jsonOptions);

                    if (!string.IsNullOrEmpty(authResponse?.Token))
                    {
                        // Store tokens
                        await SecureStorage.SetAsync(_tokenStorageKey, authResponse.Token);
                        if (!string.IsNullOrEmpty(authResponse.RefreshToken))
                            await SecureStorage.SetAsync(_refreshTokenStorageKey, authResponse.RefreshToken);

                        // Store user data
                        await StoreUserData(authResponse.User);

                        // Update authentication state
                        var claims = ParseTokenClaims(authResponse.Token);
                        var identity = new ClaimsIdentity(claims, "jwt");
                        var user = new ClaimsPrincipal(identity);
                        _authenticatedState = new AuthenticationState(user);
                        _isAuthenticated = true;

                        UpdateCurrentUserInfo(claims);

                        // Set authorization header for future requests
                        _httpClient.DefaultRequestHeaders.Authorization =
                            new AuthenticationHeaderValue("Bearer", authResponse.Token);

                        // Notify state change
                        NotifyAuthenticationStateChanged(Task.FromResult(_authenticatedState));

                        LoginStatus = LoginStatus.Success;
                        return LoginStatus;
                    }
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    try
                    {
                        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(errorContent, _jsonOptions);
                        LoginFailureMessage = errorResponse?.Message ?? "Invalid email or password";
                    }
                    catch
                    {
                        LoginFailureMessage = "Invalid email or password";
                    }
                    LoginStatus = LoginStatus.Failed;
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Network error during login");
                LoginFailureMessage = "Network error. Please check your connection.";
                LoginStatus = LoginStatus.Failed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error");
                LoginFailureMessage = $"Login error: {ex.Message}";
                LoginStatus = LoginStatus.Failed;
            }

            return LoginStatus;
        }

        // =============== LOGOUT ===============
        public async Task Logout()
        {
            try
            {
                // Call logout endpoint if needed
                var token = await SecureStorage.GetAsync(_tokenStorageKey);
                if (!string.IsNullOrEmpty(token))
                {
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    await _httpClient.PostAsync($"{_apiBaseUrl}/auth/logout", null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout API call");
                // Continue with local logout even if API call fails
            }
            finally
            {
                // Clear local storage
                SecureStorage.Remove(_tokenStorageKey);
                SecureStorage.Remove(_refreshTokenStorageKey);
                SecureStorage.Remove(_userStorageKey);

                // Clear authorization header
                _httpClient.DefaultRequestHeaders.Authorization = null;

                // Reset state
                _isAuthenticated = false;
                _authenticatedState = _unauthenticatedState;
                CurrentUserName = string.Empty;
                CurrentUserEmail = string.Empty;
                CurrentUserId = Guid.Empty;
                LoginStatus = LoginStatus.None;
                LoginFailureMessage = string.Empty;
                ClearSelectedImage();

                // Notify state change
                NotifyAuthenticationStateChanged(Task.FromResult(_unauthenticatedState));
            }
        }

        // =============== TOKEN REFRESH ===============
        public async Task<bool> RefreshToken()
        {
            try
            {
                var refreshToken = await SecureStorage.GetAsync(_refreshTokenStorageKey);
                if (string.IsNullOrEmpty(refreshToken))
                    return false;

                var refreshData = new { RefreshToken = refreshToken };
                var json = JsonSerializer.Serialize(refreshData, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_apiBaseUrl}/auth/refresh", content);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var authResponse = JsonSerializer.Deserialize<AuthResponse>(responseContent, _jsonOptions);

                    if (!string.IsNullOrEmpty(authResponse?.Token))
                    {
                        await SecureStorage.SetAsync(_tokenStorageKey, authResponse.Token);
                        if (!string.IsNullOrEmpty(authResponse.RefreshToken))
                            await SecureStorage.SetAsync(_refreshTokenStorageKey, authResponse.RefreshToken);

                        // Update authorization header
                        _httpClient.DefaultRequestHeaders.Authorization =
                            new AuthenticationHeaderValue("Bearer", authResponse.Token);

                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
            }

            await Logout(); // Force logout if refresh fails
            return false;
        }

        // =============== HELPER METHODS ===============
        private async Task InitializeFromStorage()
        {
            try
            {
                var token = await SecureStorage.GetAsync(_tokenStorageKey);
                if (!string.IsNullOrEmpty(token) && IsValidJwtFormat(token))
                {
                    // Validate token and create authentication state
                    var claims = ParseTokenClaims(token);
                    var identity = new ClaimsIdentity(claims, "jwt");
                    var user = new ClaimsPrincipal(identity);
                    _authenticatedState = new AuthenticationState(user);
                    _isAuthenticated = true;

                    UpdateCurrentUserInfo(claims);

                    // Set default Authorization header for API calls
                    _httpClient.DefaultRequestHeaders.Authorization =
                        new AuthenticationHeaderValue("Bearer", token);
                }
                else
                {
                    // Clear invalid token
                    if (!string.IsNullOrEmpty(token))
                    {
                        SecureStorage.Remove(_tokenStorageKey);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing from storage");
                // Clear any potentially corrupted data
                SecureStorage.Remove(_tokenStorageKey);
                SecureStorage.Remove(_refreshTokenStorageKey);
                SecureStorage.Remove(_userStorageKey);
            }
        }

        private List<Claim> ParseTokenClaims(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();

                // Ensure the token is valid before parsing
                if (!handler.CanReadToken(token))
                    throw new InvalidOperationException("Invalid JWT token format");

                var jwtToken = handler.ReadJwtToken(token);
                return jwtToken.Claims.ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing JWT token");
                throw;
            }
        }

        private bool IsValidJwtFormat(string token)
        {
            return !string.IsNullOrEmpty(token) &&
                   token.Contains('.') &&
                   token.Split('.').Length == 3;
        }

        private void UpdateCurrentUserInfo(List<Claim> claims)
        {
            CurrentUserName = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                            ?? claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                            ?? claims.FirstOrDefault(c => c.Type == "name")?.Value
                            ?? string.Empty;

            CurrentUserEmail = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                             ?? claims.FirstOrDefault(c => c.Type == "email")?.Value
                             ?? string.Empty;

            var userIdClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
                            ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (Guid.TryParse(userIdClaim, out var userId))
                CurrentUserId = userId;
            else
                CurrentUserId = Guid.Empty;
        }

        private async Task StoreUserData(UserData? userData)
        {
            if (userData != null)
            {
                var json = JsonSerializer.Serialize(userData, _jsonOptions);
                await SecureStorage.SetAsync(_userStorageKey, json);

                // Update current user info
                CurrentUserId = userData.Id;
                CurrentUserName = userData.Username;
                CurrentUserEmail = userData.Email;
            }
        }

        public async Task<UserData?> GetStoredUserData()
        {
            try
            {
                var json = await SecureStorage.GetAsync(_userStorageKey);
                if (!string.IsNullOrEmpty(json))
                {
                    return JsonSerializer.Deserialize<UserData>(json, _jsonOptions);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving stored user data");
            }

            return null;
        }

        // =============== PROFILE MANAGEMENT ===============
        public async Task<bool> UpdateProfile(ProfileUpdateRequest updateRequest)
        {
            try
            {
                var token = await SecureStorage.GetAsync(_tokenStorageKey);
                if (string.IsNullOrEmpty(token))
                    return false;

                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", token);

                var json = JsonSerializer.Serialize(updateRequest, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PutAsync($"{_apiBaseUrl}/users/profile", content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating profile");
                return false;
            }
        }

        // =============== FORCE AUTH STATE REFRESH ===============
        public void ForceStateRefresh()
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}