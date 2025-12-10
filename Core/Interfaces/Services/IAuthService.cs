using Core.DTOs.Auth;
using Core.Entities;

namespace Core.Interfaces.Services;

public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);
    Task VerifyEmailAsync(VerifyEmailRequest request);
    Task SendVerificationEmailAsync(string email);
    Task SendPasswordResetEmailAsync(ForgotPasswordRequest request);
    Task ResetPasswordAsync(ResetPasswordRequest request);
    Task RevokeRefreshTokenAsync(string refreshToken);
    Task<bool> IsEmailAvailableAsync(string email);
    Task<AuthResponse> ExternalLoginAsync(string provider, string idToken);
}