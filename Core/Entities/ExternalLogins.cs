using System.ComponentModel.DataAnnotations;

namespace backend.Core.Entities
{
    public class ExternalLogin
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Provider { get; set; }

        [Required]
        public string ProviderKey { get; set; }

        [Required]
        public string Email { get; set; }

        public string? ProfilePictureUrl { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Foreign key
        public string UserId { get; set; }
        public virtual User User { get; set; }
    }
}