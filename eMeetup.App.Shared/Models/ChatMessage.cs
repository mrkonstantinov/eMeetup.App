namespace eMeetup.App.Shared.Models;

public class ChatMessage
{
    public int Id { get; set; }
    public int InstanceId { get; set; }
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime SentAt { get; set; }
    public bool IsSystemMessage { get; set; }
    public bool IsEdited { get; set; }
    public DateTime? EditedAt { get; set; }
}