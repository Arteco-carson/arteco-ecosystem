using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Collections", Schema = "dbo")]
    public class Collection
    {
        [Key]
        public int CollectionId { get; set; }

        [Required]
        [StringLength(100)]
        public string CollectionName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        public int? OwnerProfileId { get; set; }

        [ForeignKey("OwnerProfileId")]
        public virtual UserProfile? Owner { get; set; }

        // Navigation property to the junction table
        public virtual ICollection<CollectionArtwork> CollectionArtworks { get; set; } = new List<CollectionArtwork>();
    }
}