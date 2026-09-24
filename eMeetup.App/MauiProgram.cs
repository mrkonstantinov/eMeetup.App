using eMeetup.App.Services;
using eMeetup.App.Shared.Configuration;
using eMeetup.App.Shared.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;

namespace eMeetup.App;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        builder.Services.AddMauiBlazorWebView();

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
        builder.Logging.SetMinimumLevel(LogLevel.Debug);
#endif

        // Fluent UI
        builder.Services.AddFluentUIComponents();

        // Настройки Keycloak (ОДИН РАЗ!)
        builder.Services.Configure<KeycloakSettings>(options =>
        {
            options.Authority = "https://localhost:6001/realms/emeetup";
            options.TokenEndpoint = "https://localhost:6001/realms/emeetup/protocol/openid-connect/token";
            options.LogoutEndpoint = "https://localhost:6001/realms/emeetup/protocol/openid-connect/logout";
            options.ClientId = "emeetup-public-client";
            options.ApiBaseUrl = "http://localhost:5000";
        });

        // HttpClient для AuthService
        builder.Services.AddHttpClient<AuthService>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .ConfigurePrimaryHttpMessageHandler(() =>
        {
            var handler = new HttpClientHandler();
#if DEBUG
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
#endif
            return handler;
        });

        // ✅ РЕГИСТРАЦИЯ СЕРВИСОВ (ОДИН РАЗ!)
        builder.Services.AddScoped<IAuthService, AuthService>();
        //builder.Services.AddScoped<IActivityService, ActivityService>();

        return builder.Build();
    }
}