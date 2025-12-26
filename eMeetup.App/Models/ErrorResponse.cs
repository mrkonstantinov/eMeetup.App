namespace eMeetup.App.Models;

public class ErrorResponse
{
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, string[]> Errors { get; set; } = new();
}
