using System.ComponentModel.DataAnnotations;

namespace Core.DTOs.Auth;

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(100)]
    public string Email { get; set; } = null!;

    [Required]
    [MinLength(2)]
    [MaxLength(100)]
    public string FirstName { get; set; } = null!;

    [Required]
    [MinLength(2)]
    [MaxLength(100)]
    public string LastName { get; set; } = null!;

    [Required]
    [MinLength(6)]
    [MaxLength(100)]
    public string Password { get; set; } = null!;

    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; } = null!;

    [Required]
    public string Role { get; set; } = null!; // "Recruiter" or "JobSeeker"

    [MaxLength(100)]
    public string? CompanyName { get; set; }

    [MaxLength(100)]
    public string? JobTitle { get; set; }

    [MaxLength(20)]
    [Phone]
    public string? PhoneNumber { get; set; }
}