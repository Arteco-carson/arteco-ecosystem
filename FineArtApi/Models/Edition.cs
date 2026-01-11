using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Editions", Schema = "dbo")]
    public class Edition
    {
        [Key]
        public int EditionId { get; set; }

        [StringLength(100)]
        public string? EditionType { get; set; }

        [StringLength(100)]
        public string? Marking { get; set; }

        [StringLength(100)]
        public string? EstimatedValueRelative { get; set; }

        [StringLength(100)]
        public string? Rarity { get; set; }
        
        public virtual ICollection<Artwork> Artworks { get; set; } = new List<Artwork>();
    }
}