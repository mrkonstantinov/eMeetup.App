namespace eMeetup.App.Models;

public class UserData
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public DateTime DateOfBirth { get; set; }
    public Gender Gender { get; set; }
    public string? Bio { get; set; }
    public string? ProfilePictureUrl { get; set; } // This will come from API response
    public string? City { get; set; }
    public string? Country { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string? Interests { get; set; }
    public List<string> Roles { get; set; } = new();
}