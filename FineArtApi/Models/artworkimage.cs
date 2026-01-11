using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("ArtworkImages", Schema = "dbo")]
    public class ArtworkImage
    {
        [Key]
        public int ImageId { get; set; }

        // Matches SQL: [ArtworkId] [int] NULL
        public int? ArtworkId { get; set; }

        [Required]
        [StringLength(500)]
        public string BlobUrl { get; set; } = string.Empty;

        [StringLength(500)]
        public string? ThumbnailUrl { get; set; }

        // Matches SQL: [IsPrimary] [bit] NULL
        public bool? IsPrimary { get; set; }

        // Matches SQL: [UploadedAt] [datetime2](7) NULL
        public DateTime? UploadedAt { get; set; } = DateTime.UtcNow;

        // Navigation Property back to parent Artwork
        [ForeignKey("ArtworkId")]
        public virtual Artwork? Artwork { get; set; }
    }
}