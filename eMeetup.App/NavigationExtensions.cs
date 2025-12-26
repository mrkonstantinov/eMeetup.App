using Microsoft.AspNetCore.Components;

namespace eMeetup.App;

public static class NavigationExtensions
{
    public static string GetQueryParameter(this NavigationManager navigation, string key)
    {
        var uri = navigation.ToAbsoluteUri(navigation.Uri);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        return query[key] ?? string.Empty;
    }
}