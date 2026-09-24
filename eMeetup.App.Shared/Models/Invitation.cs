namespace eMeetup.App.Shared.Models;

public class Invitation
{
    public int Id { get; set; }
    public int InstanceId { get; set; }
    public int InviterId { get; set; }
    public int InviteeId { get; set; }
    public string Status { get; set; } = "Pending";
    public string? Message { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RespondedAt { get; set; }
    public bool IsRead { get; set; }
}