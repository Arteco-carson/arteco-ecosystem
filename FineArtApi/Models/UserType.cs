using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FineArtApi.Models
{
    [Table("UserTypes", Schema = "dbo")]
    public class UserType
    {
        [Key]
        public int UserTypeId { get; set; }

        [Required]
        [StringLength(50)]
        public string UserTypeName { get; set; } = string.Empty;
    }
}