using backend.Core.Entities;
using backend.Core.Enums;
using Microsoft.AspNetCore.Identity;

public class User : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string? CompanyName { get; set; }
    public UserType UserType { get; set; }
    public string? ProfilePictureUrl { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    // These are still needed for JWT refresh tokens
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }

    // Navigation properties
    public JobSeekerProfile? JobSeekerProfile { get; set; }
    public RecruiterProfile? RecruiterProfile { get; set; }
    public CompanyProfile? CompanyProfile { get; set; }
}