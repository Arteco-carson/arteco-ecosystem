using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Artworks", Schema = "dbo")]
    public class Artwork
    {
        [Key]
        [Column("ArtworkId")]
        public int ArtworkId { get; set; }

        [Required]
        [StringLength(200)]
        public string Title { get; set; } = string.Empty;

        public int? ArtistId { get; set; }
        
        [ForeignKey("ArtistId")]
        public virtual Artist? Artist { get; set; }

        public int? CurrentLocationId { get; set; }

        public string? Medium { get; set; }

        [Column(TypeName = "decimal(10, 2)")]
        public decimal? HeightCM { get; set; }

        [Column(TypeName = "decimal(10, 2)")]
        public decimal? WidthCM { get; set; }

        [Column(TypeName = "decimal(10, 2)")]
        public decimal? DepthCM { get; set; }

        [Column(TypeName = "decimal(10, 2)")]
        public decimal? WeightKG { get; set; }

        [StringLength(50)]
        public string? CreationDateDisplay { get; set; }

        [Column("AcquisitionCost", TypeName = "decimal(19, 4)")]
        public decimal? AcquisitionCost { get; set; }

        public DateTime? AcquisitionDate { get; set; }

        public string? ProvenanceText { get; set; }

        public string? Status { get; set; }

        public bool? Frame { get; set; }

        [StringLength(50)]
        public string? LotNumber { get; set; }

        public int? EditionId { get; set; }

        [ForeignKey("EditionId")]
        public virtual Edition? Edition { get; set; }

        // Added to resolve CS1061 and match SQL schema for ownership filtering
        public int? CreatedByProfileId { get; set; }
        
        public DateTime? CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastModifiedAt { get; set; } = DateTime.UtcNow;

        // --- NAVIGATION PROPERTIES ---
        
        public virtual ICollection<ArtworkImage> ArtworkImages { get; set; } = new List<ArtworkImage>();
        
        public virtual ICollection<CollectionArtwork> CollectionArtworks { get; set; } = new List<CollectionArtwork>();

        public virtual ICollection<Appraisal> Appraisals { get; set; } = new List<Appraisal>();

        public virtual ICollection<DefectReport> DefectReports { get; set; } = new List<DefectReport>();
    }
}