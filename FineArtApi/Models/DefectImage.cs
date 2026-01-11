using System;
using System.ComponentModel.DataAnnotations;

namespace FineArtApi.Models
{
    public class DefectImage
    {
        [Key]
        public int DefectImageId { get; set; }
        public int DefectReportId { get; set; }
        public required string RawImageUrl { get; set; }
        public string? AnnotatedImageUrl { get; set; }
        public string? AnnotationMetadata { get; set; }
        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    }
}