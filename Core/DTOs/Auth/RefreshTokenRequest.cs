// RefreshTokenRequest.cs
using System.ComponentModel.DataAnnotations;

public class RefreshTokenRequest
{
    [Required]
    public string Token { get; set; }

    [Required]
    public string RefreshToken { get; set; }
}

// VerifyEmailRequest.cs (keep existing)
public class VerifyEmailRequest
{
    [Required]
    public string UserId { get; set; }

    [Required]
    public string Token { get; set; }
}

// ResendVerificationEmailRequest.cs
public class ResendVerificationEmailRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}

// ForgotPasswordRequest.cs (keep existing)
public class ForgotPasswordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}

// ResetPasswordRequest.cs (keep existing)
public class ResetPasswordRequest
{
    [Required]
    public string UserId { get; set; }

    [Required]
    public string Token { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string NewPassword { get; set; }
}

// ExternalLoginRequest.cs
public class ExternalLoginRequest
{
    [Required]
    public string Provider { get; set; }

    [Required]
    public string Token { get; set; }

    public string? UserType { get; set; }
}