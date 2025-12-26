namespace eMeetup.App.Models;

public class RegistrationResponse
{
    public bool Success { get; set; }
    public Guid UserId { get; set; }
    public string Message { get; set; } = string.Empty;
}
