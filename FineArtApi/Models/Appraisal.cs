using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Appraisals", Schema = "dbo")]
    public class Appraisal
    {
        [Key]
        public int AppraisalId { get; set; }

        public int? ArtworkId { get; set; }

        [Required]
        [Column(TypeName = "decimal(19, 4)")] // Precision for UK financial accuracy
        public decimal ValuationAmount { get; set; }

        [StringLength(3)]
        public string? CurrencyCode { get; set; } = "GBP"; // Default to GBP

        [Required]
        public DateTime ValuationDate { get; set; }

        [StringLength(200)]
        public string? AppraiserName { get; set; }

        [Column(TypeName = "decimal(19, 4)")]
        public decimal? InsuranceValue { get; set; }

        [StringLength(500)]
        public string? Notes { get; set; }

        // Navigation property back to the Artwork
        [ForeignKey("ArtworkId")]
        public virtual Artwork? Artwork { get; set; }
    }
}