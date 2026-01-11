using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Artists", Schema = "dbo")]
    public class Artist
    {
        [Key]
        public int ArtistId { get; set; }

        [Required]
        [StringLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string LastName { get; set; } = string.Empty;

        [StringLength(100)]
        public string? Pseudonym { get; set; } // Matches SQL

        public string? Biography { get; set; }

        public string? Nationality { get; set; }

        [StringLength(500)]
        public string? ProfileImageUrl { get; set; }

        // Using int to match SQL schema [BirthYear] [int]
        public int? BirthYear { get; set; }

        public int? DeathYear { get; set; }

        public DateTime? CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation property to link back to Artworks
        public virtual ICollection<Artwork> Artworks { get; set; } = new List<Artwork>();
    }
}