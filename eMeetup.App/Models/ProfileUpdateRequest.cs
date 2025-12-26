namespace eMeetup.App.Models;

public class ProfileUpdateRequest
{
    public string? Bio { get; set; }
    public string? City { get; set; }
    public string? Country { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string? Interests { get; set; }
}