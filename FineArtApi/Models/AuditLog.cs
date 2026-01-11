using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("AuditLogs")]
    public class AuditLog
    {
        [Key]
        public long LogId { get; set; }

        [StringLength(50)]
        public string? TableName { get; set; }

        public int? RecordId { get; set; }

        [StringLength(20)]
        public string? ActionType { get; set; } // INSERT, UPDATE, DELETE

        public int? PerformedByProfileId { get; set; }

        public DateTime? ChangeTimestamp { get; set; }

        public string? OldValue { get; set; }

        public string? NewValue { get; set; }
    }
}