using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace FineArtApi.Models
{
    public class DefectReport
    {
        [Key]
        public int DefectReportId { get; set; }
        public int ArtworkId { get; set; }
        public string ReportUrl { get; set; } = null!;
        public DateTime CreatedDate { get; set; }
        public string? CreatedBy { get; set; }
        public string? Status { get; set; }
        public string? AISummary { get; set; }
        public int? TenantId { get; set; }
        public string? ReportName { get; set; }

        [ForeignKey("ArtworkId")]
        [JsonIgnore]
        public virtual Artwork? Artwork { get; set; }
        
        public virtual ICollection<DefectImage>? DefectImages { get; set; }
        public virtual ICollection<DefectConversation>? DefectConversations { get; set; }
    }
}