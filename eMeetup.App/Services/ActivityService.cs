using System.Text.Json;
using eMeetup.App.Shared.Models;
using eMeetup.App.Shared.Services;
using Microsoft.Maui.Storage;

namespace eMeetup.App.Services;

public class ActivityService : IActivityService
{
    private List<ActivityTemplate> _templates = new();
    private List<ActivityInstance> _instances = new();
    private Dictionary<int, List<ChatMessage>> _chatMessages = new();
    private List<User> _users = new();

    public ActivityService()
    {
        SeedUsers();
        SeedTemplates();
        SeedInstances();
        SeedChatMessages();
    }

    #region Seed Data

    //private void SeedUsers()
    //{
    //    _users = new List<User>
    //{
    //    // Основной пользователь
    //    new User
    //    {
    //        Id = 1,
    //        KeycloakId = "3e34ac29-bfe7-4408-8e25-fdda119f066e", // ID из вашего Keycloak
    //        Username = "demo",
    //        Email = "demo@emeetup.com",
    //        AvatarUrl = "https://i.pravatar.cc/150?img=1",
    //        CreatedAt = DateTime.UtcNow,
    //        FirstName = "Демо",
    //        LastName = "Пользователь",
    //        Bio = "Люблю велосипедные прогулки и походы! 🚴‍♂️",
    //        City = "Москва",
    //        Interests = new List<string> { "велоспорт", "походы", "фотография" },
    //        Tags = new List<string> { "активный", "спорт", "природа" },
    //        FavoriteTemplateIds = new List<int> { 1, 3 },
    //        SubscribedTemplateIds = new List<int> { 1 }
    //    },
    //    // Пользователь 2
    //    new User
    //    {
    //        Id = 2,
    //        KeycloakId = "keycloak-alex-uuid",
    //        Username = "alex",
    //        Email = "alex@emeetup.com",
    //        AvatarUrl = "https://i.pravatar.cc/150?img=2",
    //        CreatedAt = DateTime.UtcNow,
    //        FirstName = "Алексей",
    //        LastName = "Иванов",
    //        Bio = "Люблю настольные игры и хорошую компанию 🎲",
    //        City = "Санкт-Петербург",
    //        Interests = new List<string> { "настольные игры", "кино", "путешествия" },
    //        Tags = new List<string> { "интеллектуальный", "креативный" },
    //        FavoriteTemplateIds = new List<int> { 2 },
    //        SubscribedTemplateIds = new List<int> { 2, 3 }
    //    },
    //    // Пользователь 3
    //    new User
    //    {
    //        Id = 3,
    //        KeycloakId = "keycloak-maria-uuid",
    //        Username = "maria",
    //        Email = "maria@emeetup.com",
    //        AvatarUrl = "https://i.pravatar.cc/150?img=3",
    //        CreatedAt = DateTime.UtcNow,
    //        FirstName = "Мария",
    //        LastName = "Петрова",
    //        Bio = "Люблю активный отдых и природу 🌿",
    //        City = "Москва",
    //        Interests = new List<string> { "йога", "природа", "здоровье" },
    //        Tags = new List<string> { "здоровый", "активный" },
    //        FavoriteTemplateIds = new List<int> { 1, 4 },
    //        SubscribedTemplateIds = new List<int> { 1, 4 }
    //    }
    //};
    //}

    private void SeedTemplates()
    {
        _templates = new List<ActivityTemplate>
        {
            // Шаблон 1 - Вело-прогулка (создатель: demo)
            new ActivityTemplate
            {
                Id = 1,
                Title = "Вело-прогулка по парку",
                Description = "Классическая вечерняя прогулка, 15 км. Маршрут проходит через живописные места парка. Идеально для начинающих и опытных велосипедистов.",
                Type = ActivityType.Cycling,
                Location = "Центральный парк, главный вход",
                MaxParticipants = 10,
                OrganizerId = 1,
                Tags = new List<string> { "спорт", "активный", "велоспорт", "парк" },
                Difficulty = "Easy",
                IsPetFriendly = true,
                IsFamilyFriendly = true,
                RequiredEquipment = "Велосипед, шлем, вода",
                ImageUrl = "https://picsum.photos/seed/cycling/400/300",
                IsRecurring = true,
                CreatedAt = DateTime.Now.AddDays(-30),
                UpdatedAt = DateTime.Now
            },
            // Шаблон 2 - Поход в горы (создатель: alex)
            new ActivityTemplate
            {
                Id = 2,
                Title = "Поход в горы к водопаду",
                Description = "Однодневный поход к водопаду. Отличная возможность насладиться природой, свежим воздухом и активным отдыхом. Маршрут средней сложности.",
                Type = ActivityType.Hiking,
                Location = "Горная тропа, начало маршрута",
                MaxParticipants = 8,
                OrganizerId = 2,
                Tags = new List<string> { "природа", "активный", "поход", "горы" },
                Difficulty = "Medium",
                IsPetFriendly = false,
                IsFamilyFriendly = false,
                RequiredEquipment = "Треккинговые палки, вода, еда, удобная обувь",
                ImageUrl = "https://picsum.photos/seed/hiking/400/300",
                IsRecurring = true,
                CreatedAt = DateTime.Now.AddDays(-20),
                UpdatedAt = DateTime.Now
            },
            // Шаблон 3 - Настольные игры (создатель: alex)
            new ActivityTemplate
            {
                Id = 3,
                Title = "Настольные игры в клубе",
                Description = "Собираемся для игры в настольные игры. Приносите свои любимые игры или пробуйте новые! Отличный способ провести вечер в компании 🎲",
                Type = ActivityType.BoardGames,
                Location = "Клуб настольных игр 'Игротека'",
                MaxParticipants = 12,
                OrganizerId = 2,
                Tags = new List<string> { "настолки", "интеллектуальный", "друзья", "игры" },
                Difficulty = "Easy",
                IsFamilyFriendly = true,
                RequiredEquipment = "Хорошее настроение 😊",
                ImageUrl = "https://picsum.photos/seed/boardgames/400/300",
                IsRecurring = true,
                CreatedAt = DateTime.Now.AddDays(-15),
                UpdatedAt = DateTime.Now
            },
            // Шаблон 4 - Утренняя йога (создатель: maria)
            new ActivityTemplate
            {
                Id = 4,
                Title = "Утренняя йога в парке",
                Description = "Зарядитесь энергией на весь день! Утренняя йога для всех уровней подготовки. Берите коврик и хорошее настроение 🧘",
                Type = ActivityType.Other,
                Location = "Парк Дружбы, центральная поляна",
                MaxParticipants = 15,
                OrganizerId = 3,
                Tags = new List<string> { "йога", "здоровье", "утро", "природа" },
                Difficulty = "Easy",
                IsFamilyFriendly = true,
                IsPetFriendly = true,
                RequiredEquipment = "Коврик для йоги, вода",
                ImageUrl = "https://picsum.photos/seed/yoga/400/300",
                IsRecurring = true,
                CreatedAt = DateTime.Now.AddDays(-10),
                UpdatedAt = DateTime.Now
            },
            // Шаблон 5 - Вечерняя пробежка (создатель: demo)
            new ActivityTemplate
            {
                Id = 5,
                Title = "Вечерняя пробежка по набережной",
                Description = "Легкий вечерний бег по набережной. 5-7 км, темп свободный. Подходит для любого уровня подготовки 🏃",
                Type = ActivityType.Other,
                Location = "Набережная реки, у моста",
                MaxParticipants = 10,
                OrganizerId = 1,
                Tags = new List<string> { "бег", "спорт", "вечер", "здоровье" },
                Difficulty = "Medium",
                RequiredEquipment = "Удобные кроссовки, вода",
                ImageUrl = "https://picsum.photos/seed/running/400/300",
                IsRecurring = true,
                CreatedAt = DateTime.Now.AddDays(-5),
                UpdatedAt = DateTime.Now
            }
        };
    }

    private void SeedInstances()
    {
        _instances = new List<ActivityInstance>
        {
            // Встреча 1 - Вело-прогулка
            new ActivityInstance
            {
                Id = 1,
                TemplateId = 1,
                StartTime = DateTime.Now.AddDays(1).Date.AddHours(18),
                EndTime = DateTime.Now.AddDays(1).Date.AddHours(20),
                Location = "Центральный парк, главный вход",
                MaxParticipants = 10,
                Status = "Scheduled",
                CurrentParticipants = 4,
                Participants = new List<User> { _users[0], _users[2] },
                CreatedAt = DateTime.Now.AddDays(-5),
                UpdatedAt = DateTime.Now
            },
            // Встреча 2 - Вело-прогулка (следующая)
            new ActivityInstance
            {
                Id = 2,
                TemplateId = 1,
                StartTime = DateTime.Now.AddDays(8).Date.AddHours(18),
                EndTime = DateTime.Now.AddDays(8).Date.AddHours(20),
                Location = "Центральный парк, главный вход",
                MaxParticipants = 10,
                Status = "Scheduled",
                CurrentParticipants = 2,
                Participants = new List<User> { _users[0] },
                CreatedAt = DateTime.Now.AddDays(-3),
                UpdatedAt = DateTime.Now
            },
            // Встреча 3 - Поход в горы
            new ActivityInstance
            {
                Id = 3,
                TemplateId = 2,
                StartTime = DateTime.Now.AddDays(3).Date.AddHours(8),
                EndTime = DateTime.Now.AddDays(3).Date.AddHours(18),
                Location = "Горная тропа, начало маршрута",
                MaxParticipants = 8,
                Status = "Scheduled",
                CurrentParticipants = 3,
                Participants = new List<User> { _users[0], _users[1], _users[2] },
                CreatedAt = DateTime.Now.AddDays(-2),
                UpdatedAt = DateTime.Now
            },
            // Встреча 4 - Настольные игры
            new ActivityInstance
            {
                Id = 4,
                TemplateId = 3,
                StartTime = DateTime.Now.AddDays(2).Date.AddHours(19),
                EndTime = DateTime.Now.AddDays(2).Date.AddHours(23),
                Location = "Клуб настольных игр 'Игротека'",
                MaxParticipants = 12,
                Status = "Scheduled",
                CurrentParticipants = 5,
                Participants = new List<User> { _users[0], _users[1] },
                CreatedAt = DateTime.Now.AddDays(-3),
                UpdatedAt = DateTime.Now
            },
            // Встреча 5 - Утренняя йога
            new ActivityInstance
            {
                Id = 5,
                TemplateId = 4,
                StartTime = DateTime.Now.AddDays(1).Date.AddHours(7),
                EndTime = DateTime.Now.AddDays(1).Date.AddHours(8),
                Location = "Парк Дружбы, центральная поляна",
                MaxParticipants = 15,
                Status = "Scheduled",
                CurrentParticipants = 6,
                Participants = new List<User> { _users[0], _users[2] },
                CreatedAt = DateTime.Now.AddDays(-2),
                UpdatedAt = DateTime.Now
            },
            // Встреча 6 - Вечерняя пробежка
            new ActivityInstance
            {
                Id = 6,
                TemplateId = 5,
                StartTime = DateTime.Now.AddDays(3).Date.AddHours(20),
                EndTime = DateTime.Now.AddDays(3).Date.AddHours(21),
                Location = "Набережная реки, у моста",
                MaxParticipants = 10,
                Status = "Scheduled",
                CurrentParticipants = 3,
                Participants = new List<User> { _users[1], _users[2] },
                CreatedAt = DateTime.Now.AddDays(-1),
                UpdatedAt = DateTime.Now
            }
        };
    }

    private void SeedChatMessages()
    {
        // Чат для встречи 1 (Вело-прогулка)
        _chatMessages[1] = new List<ChatMessage>
        {
            new ChatMessage
            {
                Id = 1,
                InstanceId = 1,
                UserId = 1,
                Username = "demo",
                AvatarUrl = "https://i.pravatar.cc/150?img=1",
                Message = "Всем привет! Кто сегодня едет на велопрогулку? 🚴‍♂️",
                SentAt = DateTime.Now.AddHours(-2),
                IsSystemMessage = false
            },
            new ChatMessage
            {
                Id = 2,
                InstanceId = 1,
                UserId = 2,
                Username = "alex",
                AvatarUrl = "https://i.pravatar.cc/150?img=2",
                Message = "Я буду! Встречаемся у входа в парк в 18:00?",
                SentAt = DateTime.Now.AddHours(-1),
                IsSystemMessage = false
            },
            new ChatMessage
            {
                Id = 3,
                InstanceId = 1,
                UserId = 1,
                Username = "demo",
                AvatarUrl = "https://i.pravatar.cc/150?img=1",
                Message = "Да, отлично! Жду всех у главных ворот 🚲",
                SentAt = DateTime.Now.AddMinutes(-30),
                IsSystemMessage = false
            }
        };

        // Чат для встречи 3 (Поход в горы)
        _chatMessages[3] = new List<ChatMessage>
        {
            new ChatMessage
            {
                Id = 4,
                InstanceId = 3,
                UserId = 3,
                Username = "maria",
                AvatarUrl = "https://i.pravatar.cc/150?img=3",
                Message = "Привет! Кто идет в поход? Нужно брать палатку? 🏕️",
                SentAt = DateTime.Now.AddDays(-1).AddHours(-3),
                IsSystemMessage = false
            },
            new ChatMessage
            {
                Id = 5,
                InstanceId = 3,
                UserId = 1,
                Username = "demo",
                AvatarUrl = "https://i.pravatar.cc/150?img=1",
                Message = "Палатку я беру, не беспокойтесь. Берите с собой воду и еду 😊",
                SentAt = DateTime.Now.AddDays(-1).AddHours(-2),
                IsSystemMessage = false
            },
            new ChatMessage
            {
                Id = 6,
                InstanceId = 3,
                UserId = 2,
                Username = "alex",
                AvatarUrl = "https://i.pravatar.cc/150?img=2",
                Message = "Я тоже иду! Встречаемся у начала тропы в 8:00 ⛰️",
                SentAt = DateTime.Now.AddDays(-1).AddHours(-1),
                IsSystemMessage = false
            }
        };
    }

    #endregion

    #region Шаблоны

    public Task<List<ActivityTemplate>> GetTemplatesAsync() => Task.FromResult(_templates);

    public Task<ActivityTemplate?> GetTemplateAsync(int id) =>
        Task.FromResult(_templates.FirstOrDefault(t => t.Id == id));

    public Task<ActivityTemplate> CreateTemplateAsync(ActivityTemplate template)
    {
        template.Id = _templates.Count > 0 ? _templates.Max(t => t.Id) + 1 : 1;
        template.CreatedAt = DateTime.Now;
        template.UpdatedAt = DateTime.Now;
        _templates.Add(template);
        return Task.FromResult(template);
    }

    public Task<ActivityTemplate> UpdateTemplateAsync(ActivityTemplate template)
    {
        var index = _templates.FindIndex(t => t.Id == template.Id);
        if (index != -1)
        {
            template.UpdatedAt = DateTime.Now;
            _templates[index] = template;
        }
        return Task.FromResult(template);
    }

    public Task<bool> DeleteTemplateAsync(int id)
    {
        var template = _templates.FirstOrDefault(t => t.Id == id);
        if (template == null) return Task.FromResult(false);

        // Удаляем все встречи связанные с этим шаблоном
        var instances = _instances.Where(i => i.TemplateId == id).ToList();
        foreach (var instance in instances)
        {
            _instances.Remove(instance);
        }

        _templates.Remove(template);
        return Task.FromResult(true);
    }

    public Task<List<ActivityInstance>> GetTemplateInstancesAsync(int templateId) =>
        Task.FromResult(_instances.Where(i => i.TemplateId == templateId).ToList());

    public Task<List<ActivityTemplate>> GetUserTemplatesAsync(int userId) =>
        Task.FromResult(_templates.Where(t => t.OrganizerId == userId).ToList());

    #endregion

    #region Экземпляры (встречи)

    public Task<List<ActivityInstance>> GetInstancesAsync(int? templateId = null)
    {
        if (templateId.HasValue)
            return Task.FromResult(_instances.Where(i => i.TemplateId == templateId.Value).ToList());
        return Task.FromResult(_instances.ToList());
    }

    public Task<ActivityInstance?> GetInstanceAsync(int id) =>
        Task.FromResult(_instances.FirstOrDefault(i => i.Id == id));

    public Task<ActivityInstance> CreateInstanceAsync(ActivityInstance instance)
    {
        instance.Id = _instances.Count > 0 ? _instances.Max(i => i.Id) + 1 : 1;
        instance.CurrentParticipants = 0;
        instance.Status = "Scheduled";
        instance.CreatedAt = DateTime.Now;
        instance.UpdatedAt = DateTime.Now;
        _instances.Add(instance);
        return Task.FromResult(instance);
    }

    public Task<ActivityInstance> UpdateInstanceAsync(ActivityInstance instance)
    {
        var index = _instances.FindIndex(i => i.Id == instance.Id);
        if (index != -1)
        {
            instance.UpdatedAt = DateTime.Now;
            _instances[index] = instance;
        }
        return Task.FromResult(instance);
    }

    public Task<bool> DeleteInstanceAsync(int id)
    {
        var instance = _instances.FirstOrDefault(i => i.Id == id);
        if (instance == null) return Task.FromResult(false);
        _instances.Remove(instance);
        return Task.FromResult(true);
    }

    public Task<bool> CancelInstanceAsync(int id, string reason)
    {
        var instance = _instances.FirstOrDefault(i => i.Id == id);
        if (instance == null) return Task.FromResult(false);
        instance.Status = "Cancelled";
        instance.CancellationReason = reason;
        instance.UpdatedAt = DateTime.Now;
        return Task.FromResult(true);
    }

    public Task<bool> JoinInstanceAsync(int instanceId, int userId)
    {
        var instance = _instances.FirstOrDefault(i => i.Id == instanceId);
        if (instance == null || instance.Status == "Cancelled") return Task.FromResult(false);

        var template = _templates.FirstOrDefault(t => t.Id == instance.TemplateId);
        var maxParticipants = instance.MaxParticipants ?? template?.MaxParticipants ?? 10;

        if (instance.CurrentParticipants >= maxParticipants) return Task.FromResult(false);

        if (!instance.Participants.Any(p => p.Id == userId))
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user != null)
            {
                instance.Participants.Add(user);
                instance.CurrentParticipants++;
                instance.UpdatedAt = DateTime.Now;
            }
        }
        return Task.FromResult(true);
    }

    public Task<bool> LeaveInstanceAsync(int instanceId, int userId)
    {
        var instance = _instances.FirstOrDefault(i => i.Id == instanceId);
        if (instance == null) return Task.FromResult(false);

        var participant = instance.Participants.FirstOrDefault(p => p.Id == userId);
        if (participant != null)
        {
            instance.Participants.Remove(participant);
            instance.CurrentParticipants--;
            instance.UpdatedAt = DateTime.Now;
        }
        return Task.FromResult(true);
    }

    #endregion

    #region Поиск и фильтрация

    public Task<List<ActivityInstance>> SearchInstancesAsync(
        string? query,
        List<string>? tags,
        ActivityType? type,
        DateTime? fromDate,
        DateTime? toDate,
        bool includeCompleted = false)
    {
        var result = _instances.AsEnumerable();

        if (!includeCompleted)
            result = result.Where(i => i.Status != "Completed" && i.Status != "Cancelled");

        if (!string.IsNullOrWhiteSpace(query))
        {
            query = query.ToLower();
            result = result.Where(i =>
                (i.Template?.Title?.ToLower().Contains(query) ?? false) ||
                (i.Template?.Description?.ToLower().Contains(query) ?? false) ||
                (i.Location?.ToLower().Contains(query) ?? false) ||
                (i.Template?.Location?.ToLower().Contains(query) ?? false));
        }

        if (tags != null && tags.Any())
        {
            result = result.Where(i => i.Template != null && i.Template.Tags.Any(t => tags.Contains(t)));
        }

        if (type.HasValue)
        {
            result = result.Where(i => i.Template != null && i.Template.Type == type.Value);
        }

        if (fromDate.HasValue)
            result = result.Where(i => i.StartTime >= fromDate.Value);
        if (toDate.HasValue)
            result = result.Where(i => i.EndTime <= toDate.Value);

        return Task.FromResult(result.ToList());
    }

    public Task<List<ActivityInstance>> GetUserUpcomingInstancesAsync(int userId)
    {
        var now = DateTime.Now;
        return Task.FromResult(_instances
            .Where(i => i.Participants.Any(p => p.Id == userId) && i.StartTime > now && i.Status != "Cancelled")
            .OrderBy(i => i.StartTime)
            .ToList());
    }

    public Task<List<ActivityInstance>> GetUserPastInstancesAsync(int userId)
    {
        var now = DateTime.Now;
        return Task.FromResult(_instances
            .Where(i => i.Participants.Any(p => p.Id == userId) && i.StartTime < now)
            .OrderByDescending(i => i.StartTime)
            .ToList());
    }

    #endregion

    #region ⭐ Избранное

    public async Task<bool> AddToFavoritesAsync(int userId, int templateId)
    {
        try
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user == null) return false;

            var template = _templates.FirstOrDefault(t => t.Id == templateId);
            if (template == null) return false;

            if (!user.FavoriteTemplateIds.Contains(templateId))
            {
                user.FavoriteTemplateIds.Add(templateId);
                await UpdateUserInStorage(user);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> RemoveFromFavoritesAsync(int userId, int templateId)
    {
        try
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user == null) return false;

            if (user.FavoriteTemplateIds.Contains(templateId))
            {
                user.FavoriteTemplateIds.Remove(templateId);
                await UpdateUserInStorage(user);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> IsFavoriteAsync(int userId, int templateId)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return false;
        return user.FavoriteTemplateIds.Contains(templateId);
    }

    public async Task<List<ActivityTemplate>> GetFavoriteTemplatesAsync(int userId)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return new List<ActivityTemplate>();

        return _templates.Where(t => user.FavoriteTemplateIds.Contains(t.Id)).ToList();
    }

    #endregion

    #region 🔔 Подписки

    public async Task<bool> SubscribeAsync(int userId, int templateId)
    {
        try
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user == null) return false;

            var template = _templates.FirstOrDefault(t => t.Id == templateId);
            if (template == null) return false;

            if (!user.SubscribedTemplateIds.Contains(templateId))
            {
                user.SubscribedTemplateIds.Add(templateId);

                // Автоматически добавляем в избранное
                if (!user.FavoriteTemplateIds.Contains(templateId))
                {
                    user.FavoriteTemplateIds.Add(templateId);
                }

                await UpdateUserInStorage(user);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> UnsubscribeAsync(int userId, int templateId)
    {
        try
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user == null) return false;

            if (user.SubscribedTemplateIds.Contains(templateId))
            {
                user.SubscribedTemplateIds.Remove(templateId);
                await UpdateUserInStorage(user);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> IsSubscribedAsync(int userId, int templateId)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return false;
        return user.SubscribedTemplateIds.Contains(templateId);
    }

    public async Task<List<ActivityTemplate>> GetSubscribedTemplatesAsync(int userId)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return new List<ActivityTemplate>();

        return _templates.Where(t => user.SubscribedTemplateIds.Contains(t.Id)).ToList();
    }

    #endregion

    #region Чат

    public Task<List<ChatMessage>> GetChatMessagesAsync(int instanceId)
    {
        if (!_chatMessages.ContainsKey(instanceId))
            _chatMessages[instanceId] = new List<ChatMessage>();
        return Task.FromResult(_chatMessages[instanceId].OrderBy(m => m.SentAt).ToList());
    }

    public async Task<ChatMessage?> SendChatMessageAsync(int instanceId, int userId, string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return null;

        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return null;

        var instance = await GetInstanceAsync(instanceId);
        if (instance == null) return null;

        if (!instance.Participants.Any(p => p.Id == userId) &&
            !_templates.Any(t => t.Id == instance.TemplateId && t.OrganizerId == userId))
            return null;

        if (!_chatMessages.ContainsKey(instanceId))
            _chatMessages[instanceId] = new List<ChatMessage>();

        var chatMessage = new ChatMessage
        {
            Id = _chatMessages[instanceId].Count > 0 ? _chatMessages[instanceId].Max(m => m.Id) + 1 : 1,
            InstanceId = instanceId,
            UserId = userId,
            Username = user.Username,
            AvatarUrl = user.AvatarUrl,
            Message = message,
            SentAt = DateTime.Now,
            IsSystemMessage = false
        };

        _chatMessages[instanceId].Add(chatMessage);
        return chatMessage;
    }

    public Task<bool> DeleteChatMessageAsync(int messageId, int userId)
    {
        foreach (var messages in _chatMessages.Values)
        {
            var message = messages.FirstOrDefault(m => m.Id == messageId);
            if (message != null && message.UserId == userId)
            {
                messages.Remove(message);
                return Task.FromResult(true);
            }
        }
        return Task.FromResult(false);
    }

    public Task<bool> EditChatMessageAsync(int messageId, int userId, string newMessage)
    {
        if (string.IsNullOrWhiteSpace(newMessage)) return Task.FromResult(false);

        foreach (var messages in _chatMessages.Values)
        {
            var message = messages.FirstOrDefault(m => m.Id == messageId);
            if (message != null && message.UserId == userId)
            {
                message.Message = newMessage;
                message.IsEdited = true;
                message.EditedAt = DateTime.Now;
                return Task.FromResult(true);
            }
        }
        return Task.FromResult(false);
    }

    #endregion

    #region Вспомогательные методы

    private async Task UpdateUserInStorage(User user)
    {
        try
        {
            // Обновляем пользователя в списке
            var index = _users.FindIndex(u => u.Id == user.Id);
            if (index != -1)
            {
                _users[index] = user;
            }

            // Если это текущий пользователь - обновляем в SecureStorage
            var currentUserJson = await SecureStorage.GetAsync("current_user");
            if (!string.IsNullOrEmpty(currentUserJson))
            {
                var currentUser = JsonSerializer.Deserialize<User>(currentUserJson);
                if (currentUser != null && currentUser.Id == user.Id)
                {
                    var updatedJson = JsonSerializer.Serialize(user);
                    await SecureStorage.SetAsync("current_user", updatedJson);
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"UpdateUserInStorage error: {ex.Message}");
        }
    }

    #endregion
}