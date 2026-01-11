using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;

namespace FineArtApi.Models
{
    [Table("UserLocations", Schema = "dbo")]
    [PrimaryKey(nameof(ProfileId), nameof(LocationId))]
    public class UserLocation
    {
        public int ProfileId { get; set; }

        public int LocationId { get; set; }

        public bool? IsDefault { get; set; }

        public DateTime? AssignedDate { get; set; }

        [ForeignKey("ProfileId")]
        [JsonIgnore]
        public virtual UserProfile UserProfile { get; set; } = null!;

        [ForeignKey("LocationId")]
        [JsonIgnore]
        public virtual Location Location { get; set; } = null!;
    }
}