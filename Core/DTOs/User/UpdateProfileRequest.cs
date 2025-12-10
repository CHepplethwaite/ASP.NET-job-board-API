using System.ComponentModel.DataAnnotations;

namespace Core.DTOs.User;

public class UpdateProfileRequest
{
    [MaxLength(100)]
    public string? FirstName { get; set; }

    [MaxLength(100)]
    public string? LastName { get; set; }

    [MaxLength(20)]
    [Phone]
    public string? PhoneNumber { get; set; }

    [MaxLength(100)]
    public string? CompanyName { get; set; }

    [MaxLength(100)]
    public string? JobTitle { get; set; }
}