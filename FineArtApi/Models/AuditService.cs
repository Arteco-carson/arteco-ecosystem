using FineArtApi.Data;
using FineArtApi.Models;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System;

namespace FineArtApi.Services
{
    public interface IAuditService
    {
        Task LogAsync(string tableName, int recordId, string actionType, int performedByProfileId, object? oldValue, object? newValue);
    }

    public class AuditService : IAuditService
    {
        private readonly ArtContext _context;

        public AuditService(ArtContext context)
        {
            _context = context;
        }

        public async Task LogAsync(string tableName, int recordId, string actionType, int performedByProfileId, object? oldValue, object? newValue)
        {
            var options = new JsonSerializerOptions
            {
                ReferenceHandler = ReferenceHandler.IgnoreCycles,
                WriteIndented = false
            };

            var log = new AuditLog
            {
                TableName = tableName,
                RecordId = recordId,
                ActionType = actionType,
                PerformedByProfileId = performedByProfileId,
                ChangeTimestamp = DateTime.UtcNow,
                OldValue = oldValue != null ? JsonSerializer.Serialize(oldValue, options) : null,
                NewValue = newValue != null ? JsonSerializer.Serialize(newValue, options) : null
            };

            _context.Set<AuditLog>().Add(log);
            await _context.SaveChangesAsync();
        }
    }
}