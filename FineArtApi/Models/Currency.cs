using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("Currencies", Schema = "dbo")]
    public class Currency
    {
        [Key]
        [StringLength(3)]
        public string CurrencyCode { get; set; } = null!;

        [Required]
        [StringLength(30)]
        public string CurrencyName { get; set; } = null!;

        [StringLength(30)]
        public string? Country { get; set; }

        [Column(TypeName = "decimal(10, 4)")]
        public decimal? BuyRate { get; set; }

        [Column(TypeName = "decimal(10, 4)")]
        public decimal? SellRate { get; set; }
    }
}