namespace eMeetup.App.Shared.Models;

public class Notification
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? Link { get; set; }
    public int? RelatedId { get; set; }
    public bool IsRead { get; set; }
    public bool IsSystem { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime? ReadAt { get; set; }
}
