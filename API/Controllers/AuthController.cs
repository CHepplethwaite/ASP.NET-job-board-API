using Core.DTOs.Auth;
using Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var response = await _authService.RegisterAsync(request);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var response = await _authService.LoginAsync(request);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login");
            return Unauthorized(new { message = ex.Message });
        }
    }

    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var response = await _authService.RefreshTokenAsync(request.RefreshToken);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return Unauthorized(new { message = ex.Message });
        }
    }

    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        try
        {
            await _authService.VerifyEmailAsync(request);
            return Ok(new { message = "Email verified successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying email");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("resend-verification")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request)
    {
        try
        {
            await _authService.SendVerificationEmailAsync(request.Email);
            return Ok(new { message = "Verification email sent" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resending verification email");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("forgot-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        // Always return OK to prevent email enumeration
        await _authService.SendPasswordResetEmailAsync(request);
        return Ok(new { message = "If the email exists, a reset link has been sent" });
    }

    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            await _authService.ResetPasswordAsync(request);
            return Ok(new { message = "Password reset successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        await _authService.RevokeRefreshTokenAsync(request.RefreshToken);
        return Ok(new { message = "Logged out successfully" });
    }

    [HttpGet("check-email/{email}")]
    [ProducesResponseType(typeof(EmailAvailabilityResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> CheckEmailAvailability(string email)
    {
        var isAvailable = await _authService.IsEmailAvailableAsync(email);
        return Ok(new EmailAvailabilityResponse { IsAvailable = isAvailable });
    }

    [HttpPost("external/{provider}")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ExternalLogin(string provider, [FromBody] ExternalLoginRequest request)
    {
        try
        {
            var response = await _authService.ExternalLoginAsync(provider, request.IdToken);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during external login");
            return BadRequest(new { message = ex.Message });
        }
    }
}

// Additional DTOs for AuthController
public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = null!;
}

public class ResendVerificationRequest
{
    public string Email { get; set; } = null!;
}

public class LogoutRequest
{
    public string RefreshToken { get; set; } = null!;
}

public class EmailAvailabilityResponse
{
    public bool IsAvailable { get; set; }
}

public class ExternalLoginRequest
{
    public string IdToken { get; set; } = null!;
}