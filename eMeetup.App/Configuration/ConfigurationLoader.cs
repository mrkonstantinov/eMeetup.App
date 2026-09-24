using Microsoft.Extensions.Configuration;
using System.Reflection;

namespace eMeetup.App.Configuration;

public static class ConfigurationLoader
{
    public static IConfiguration LoadConfiguration()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = assembly.GetManifestResourceNames()
                .FirstOrDefault(r => r.EndsWith("appsettings.json"));

            if (resourceName != null)
            {
                var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream != null)
                {
                    var config = new ConfigurationBuilder()
                        .AddJsonStream(stream)
                        .Build();

                    // ✅ Переопределяем для Android
                    if (DeviceInfo.Current.Platform == DevicePlatform.Android)
                    {
                        var baseUrl = GetAndroidBaseUrl();

                        var overrides = new Dictionary<string, string?>
                        {
                            ["Keycloak:Authority"] = $"{baseUrl}/realms/emeetup",
                            ["Keycloak:TokenEndpoint"] = $"{baseUrl}/realms/emeetup/protocol/openid-connect/token",
                            ["Keycloak:ApiBaseUrl"] = $"{baseUrl.Replace(":6001", ":5000")}"
                        };

                        config = new ConfigurationBuilder()
                            .AddConfiguration(config)
                            .AddInMemoryCollection(overrides)
                            .Build();

                        System.Diagnostics.Debug.WriteLine($"✅ Android config: {baseUrl}");
                    }

                    return config;
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"❌ Config error: {ex.Message}");
        }

        // Fallback
        return GetFallbackConfig();
    }

    private static string GetAndroidBaseUrl()
    {
        // Для Android эмулятора
        if (DeviceInfo.Current.DeviceType == DeviceType.Virtual)
        {
            return "https://10.0.2.2:6001";
        }

        // Для физического устройства - используйте IP вашего ПК
        // Например: https://192.168.1.100:6001
        return "https://10.0.2.2:6001";
    }

    private static IConfiguration GetFallbackConfig()
    {
        var baseUrl = DeviceInfo.Current.Platform == DevicePlatform.Android
            ? "https://10.0.2.2:6001"
            : "https://localhost:6001";

        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = $"{baseUrl}/realms/emeetup",
                ["Keycloak:TokenEndpoint"] = $"{baseUrl}/realms/emeetup/protocol/openid-connect/token",
                ["Keycloak:ClientId"] = "emeetup-public-client",
                ["Keycloak:ClientSecret"] = "",
                ["Keycloak:ApiBaseUrl"] = $"{baseUrl.Replace(":6001", ":7001")}/api"
            })
            .Build();
    }
}
