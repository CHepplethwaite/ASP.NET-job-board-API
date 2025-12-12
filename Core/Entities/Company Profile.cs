using System.ComponentModel.DataAnnotations;

namespace backend.Core.Entities
{
    public class CompanyProfile
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(200)]
        public string Name { get; set; }

        [MaxLength(500)]
        public string? Description { get; set; }

        [MaxLength(200)]
        public string? Industry { get; set; }

        [MaxLength(200)]
        public string? Website { get; set; }

        [MaxLength(200)]
        public string? LogoUrl { get; set; }

        [MaxLength(100)]
        public string? Size { get; set; }

        [MaxLength(200)]
        public string? Headquarters { get; set; }

        public int? FoundedYear { get; set; }

        [MaxLength(1000)]
        public string? TechStack { get; set; }

        [MaxLength(500)]
        public string? Benefits { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Foreign key
        public string UserId { get; set; }
        public virtual User User { get; set; }

        // Navigation properties
        public virtual ICollection<RecruiterProfile> Recruiters { get; set; } = new List<RecruiterProfile>();
    }
}