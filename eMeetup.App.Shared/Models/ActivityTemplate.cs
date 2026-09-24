namespace eMeetup.App.Shared.Models;

public class ActivityTemplate
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ActivityType Type { get; set; }
    public string Location { get; set; } = string.Empty;
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public int MaxParticipants { get; set; }
    public int OrganizerId { get; set; }
    public User? Organizer { get; set; }
    public List<string> Tags { get; set; } = new();
    public string? Difficulty { get; set; }
    public int? AgeRestriction { get; set; }
    public bool IsPetFriendly { get; set; }
    public bool IsFamilyFriendly { get; set; }
    public string? RequiredEquipment { get; set; }
    public string ImageUrl { get; set; } = string.Empty;
    public bool IsPrivate { get; set; }
    public bool IsRecurring { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public List<ActivityInstance> Instances { get; set; } = new();
}