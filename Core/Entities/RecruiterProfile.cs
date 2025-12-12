using System.ComponentModel.DataAnnotations;

namespace backend.Core.Entities
{
    public class RecruiterProfile
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(100)]
        public string? Department { get; set; }

        public string? Bio { get; set; }

        public int? YearsOfExperience { get; set; }

        [MaxLength(200)]
        public string? Specializations { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Foreign key
        public string UserId { get; set; }
        public virtual User User { get; set; }

        // Foreign key to company
        public int? CompanyId { get; set; }
        public virtual CompanyProfile? Company { get; set; }
    }
}