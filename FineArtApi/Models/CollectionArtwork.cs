using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("CollectionArtworks", Schema = "dbo")]
    public class CollectionArtwork
    {
        [Key, Column(Order = 0)]
        public int CollectionId { get; set; }

        [Key, Column(Order = 1)]
        public int ArtworkId { get; set; }

        public DateTime? DateAdded { get; set; }
        
        public int? AddedByProfileId { get; set; }

        // Navigation Properties
        [ForeignKey("CollectionId")]
        public virtual Collection Collection { get; set; } = null!;

        [ForeignKey("ArtworkId")]
        public virtual Artwork Artwork { get; set; } = null!;
    }
}