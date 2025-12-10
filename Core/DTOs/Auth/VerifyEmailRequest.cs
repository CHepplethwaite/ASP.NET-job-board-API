using System.ComponentModel.DataAnnotations;

namespace Core.DTOs.Auth;

public class VerifyEmailRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = null!;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string Code { get; set; } = null!;
}