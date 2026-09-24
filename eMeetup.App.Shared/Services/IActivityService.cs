using eMeetup.App.Shared.Models;

namespace eMeetup.App.Shared.Services;

public interface IActivityService
{
    // Шаблоны
    Task<List<ActivityTemplate>> GetTemplatesAsync();
    Task<ActivityTemplate?> GetTemplateAsync(int id);
    Task<ActivityTemplate> CreateTemplateAsync(ActivityTemplate template);
    Task<ActivityTemplate> UpdateTemplateAsync(ActivityTemplate template);
    Task<bool> DeleteTemplateAsync(int id);
    Task<List<ActivityInstance>> GetTemplateInstancesAsync(int templateId);
    Task<List<ActivityTemplate>> GetUserTemplatesAsync(int userId);

    // Экземпляры (встречи)
    Task<List<ActivityInstance>> GetInstancesAsync(int? templateId = null);
    Task<ActivityInstance?> GetInstanceAsync(int id);
    Task<ActivityInstance> CreateInstanceAsync(ActivityInstance instance);
    Task<ActivityInstance> UpdateInstanceAsync(ActivityInstance instance);
    Task<bool> DeleteInstanceAsync(int id);
    Task<bool> CancelInstanceAsync(int id, string reason);
    Task<bool> JoinInstanceAsync(int instanceId, int userId);
    Task<bool> LeaveInstanceAsync(int instanceId, int userId);

    // Поиск и фильтрация
    Task<List<ActivityInstance>> SearchInstancesAsync(
        string? query,
        List<string>? tags,
        ActivityType? type,
        DateTime? fromDate,
        DateTime? toDate,
        bool includeCompleted = false);

    Task<List<ActivityInstance>> GetUserUpcomingInstancesAsync(int userId);
    Task<List<ActivityInstance>> GetUserPastInstancesAsync(int userId);

    // ⭐ Избранное
    Task<bool> AddToFavoritesAsync(int userId, int templateId);
    Task<bool> RemoveFromFavoritesAsync(int userId, int templateId);
    Task<bool> IsFavoriteAsync(int userId, int templateId);
    Task<List<ActivityTemplate>> GetFavoriteTemplatesAsync(int userId);

    // 🔔 Подписки
    Task<bool> SubscribeAsync(int userId, int templateId);
    Task<bool> UnsubscribeAsync(int userId, int templateId);
    Task<bool> IsSubscribedAsync(int userId, int templateId);
    Task<List<ActivityTemplate>> GetSubscribedTemplatesAsync(int userId);

    // Чат
    Task<List<ChatMessage>> GetChatMessagesAsync(int instanceId);
    Task<ChatMessage?> SendChatMessageAsync(int instanceId, int userId, string message);
    Task<bool> DeleteChatMessageAsync(int messageId, int userId);
    Task<bool> EditChatMessageAsync(int messageId, int userId, string newMessage);
}