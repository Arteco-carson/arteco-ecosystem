using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace FineArtApi.Models
{
    [Table("UserProfiles")]
    public class UserProfile
    {
        [Key]
        public int ProfileId { get; set; }

        [Required]
        [StringLength(100)]
        public string ExternalUserId { get; set; } = null!; // Resolves CS8618

        [StringLength(100)]
        public string? FirstName { get; set; } // Nullable to match SQL schema

        [StringLength(100)]
        public string? LastName { get; set; } // Nullable to match SQL schema

        [Required]
        [StringLength(255)]
        public string EmailAddress { get; set; } = null!; // Resolves CS8618

        [StringLength(50)]
        public string? TelephoneNumber { get; set; }

        [StringLength(100)]
        public string Username { get; set; } = null!; // Resolves CS8618

        public string PasswordHash { get; set; } = null!; // Resolves CS8618

        public string? Salt { get; set; } // Matches SQL schema nullable status

        public int RoleId { get; set; }

        [ForeignKey("RoleId")]
        public virtual UserRole? Role { get; set; }

        public int? UserTypeId { get; set; }

        [ForeignKey("UserTypeId")]
        public virtual UserType? UserType { get; set; }

        [StringLength(3)]
        public string? CurrencyCode { get; set; }

        [ForeignKey("CurrencyCode")]
        public virtual Currency? Currency { get; set; }

        public bool IsActive { get; set; } = true;

        public DateTime? TermsAcceptedDate { get; set; }

        public bool MarketingConsent { get; set; }

        public DateTime? LastLoginDate { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation property for Many-to-Many relationship with Locations
        [JsonIgnore]
        public virtual ICollection<UserLocation> UserLocations { get; set; } = new List<UserLocation>();
    }
}