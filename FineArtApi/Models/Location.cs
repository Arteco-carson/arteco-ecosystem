using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace FineArtApi.Models
{
    [Table("Locations", Schema = "dbo")]
    public class Location
    {
        [Key]
        public int LocationId { get; set; }

        [Required]
        [StringLength(100)]
        public string LocationName { get; set; } = string.Empty;

        [StringLength(200)]
        public string? AddressLine1 { get; set; }

        [StringLength(100)]
        public string? City { get; set; }

        [StringLength(20)]
        public string? Postcode { get; set; }

        [StringLength(100)]
        public string? Country { get; set; }

        [StringLength(50)]
        public string? SecurityLevel { get; set; }

        public bool? IsClimateControlled { get; set; }

        public bool IsDefault { get; set; }

        [StringLength(500)]
        public string? Notes { get; set; }

        // Navigation property for Many-to-Many relationship with UserProfiles
        [JsonIgnore]
        public virtual ICollection<UserLocation> UserLocations { get; set; } = new List<UserLocation>();
    }
}