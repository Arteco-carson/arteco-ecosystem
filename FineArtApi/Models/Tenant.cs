using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    public class Tenant
    {
        [Key]
        public int TenantId { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string Subdomain { get; set; } = string.Empty;

        [StringLength(500)]
        public string? LogoUrl { get; set; }

        [StringLength(7)]
        public string? PrimaryColor { get; set; }
    }
}