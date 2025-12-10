using System.ComponentModel.DataAnnotations;

namespace Core.DTOs.Auth;

public class ResetPasswordRequest
{
    [Required]
    public string Token { get; set; } = null!;

    [Required]
    [MinLength(6)]
    [MaxLength(100)]
    public string NewPassword { get; set; } = null!;

    [Required]
    [Compare("NewPassword")]
    public string ConfirmPassword { get; set; } = null!;
}