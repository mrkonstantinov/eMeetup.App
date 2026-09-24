namespace eMeetup.App.Shared.Models;

public class ActivityInstance
{
    public int Id { get; set; }
    public int TemplateId { get; set; }
    public ActivityTemplate? Template { get; set; }

    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public string? Location { get; set; }
    public int? MaxParticipants { get; set; }

    public string Status { get; set; } = "Scheduled";
    public string? CancellationReason { get; set; }

    public int CurrentParticipants { get; set; }
    public List<User> Participants { get; set; } = new();
    public string? Notes { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public int? WeatherTemperature { get; set; }
    public string? WeatherCondition { get; set; }
    public int? ActualParticipants { get; set; }
    public string? PhotoUrl { get; set; }
}