using System;
using System.ComponentModel.DataAnnotations;

namespace FineArtApi.Models
{
    public class DefectConversation
    {
        [Key]
        public int MessageId { get; set; }
        public int DefectReportId { get; set; }
        public string? ExternalMessageId { get; set; }
        public required string Sender { get; set; }
        public string? MessageBody { get; set; }
        public string? MediaUrl { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}