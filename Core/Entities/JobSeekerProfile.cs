using System.ComponentModel.DataAnnotations;

namespace backend.Core.Entities
{
    public class JobSeekerProfile
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(200)]
        public string? Headline { get; set; }

        public string? Summary { get; set; }

        [MaxLength(100)]
        public string? CurrentPosition { get; set; }

        [MaxLength(100)]
        public string? CurrentCompany { get; set; }

        public string? Location { get; set; }

        public string? Country { get; set; }

        [MaxLength(100)]
        public string? LinkedInUrl { get; set; }

        [MaxLength(100)]
        public string? GitHubUrl { get; set; }

        [MaxLength(100)]
        public string? PortfolioUrl { get; set; }

        public decimal? DesiredSalary { get; set; }

        [MaxLength(50)]
        public string? DesiredSalaryCurrency { get; set; }

        public string? Skills { get; set; }

        public string? Languages { get; set; }

        public string? CvUrl { get; set; }

        public string? CvFileName { get; set; }

        public DateTime? CvUploadDate { get; set; }

        public bool IsOpenToWork { get; set; } = true;

        public bool IsOpenToRemote { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Foreign key
        public string UserId { get; set; }
        public virtual User User { get; set; }

        // Navigation properties
        public virtual ICollection<WorkExperience> WorkExperiences { get; set; } = new List<WorkExperience>();
        public virtual ICollection<Education> Educations { get; set; } = new List<Education>();
    }

    public class WorkExperience
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Title { get; set; }

        [Required]
        [MaxLength(100)]
        public string Company { get; set; }

        public string? Location { get; set; }

        public DateTime StartDate { get; set; }

        public DateTime? EndDate { get; set; }

        public bool IsCurrent { get; set; }

        public string? Description { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Foreign key
        public int JobSeekerProfileId { get; set; }
        public virtual JobSeekerProfile JobSeekerProfile { get; set; }
    }

    public class Education
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Institution { get; set; }

        [Required]
        [MaxLength(100)]
        public string Degree { get; set; }

        [MaxLength(100)]
        public string? FieldOfStudy { get; set; }

        public DateTime StartDate { get; set; }

        public DateTime? EndDate { get; set; }

        public string? Description { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Foreign key
        public int JobSeekerProfileId { get; set; }
        public virtual JobSeekerProfile JobSeekerProfile { get; set; }
    }
}