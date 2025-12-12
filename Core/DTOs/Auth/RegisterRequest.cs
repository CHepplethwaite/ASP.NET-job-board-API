using System.ComponentModel.DataAnnotations;

namespace backend.Core.DTOs.Auth
{
    public class RegisterRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string Password { get; set; }

        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; }

        [Phone]
        public string? PhoneNumber { get; set; }

        [Required]
        public string UserType { get; set; } // "JobSeeker", "Recruiter", "Company"

        public string? CompanyName { get; set; }
    }
}