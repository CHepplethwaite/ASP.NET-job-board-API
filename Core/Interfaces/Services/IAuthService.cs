using backend.Core.DTOs.Auth;

namespace backend.Core.Interfaces.Services
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(LoginRequest request);
        Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request);
        Task VerifyEmailAsync(VerifyEmailRequest request);
        Task ResendVerificationEmailAsync(ResendVerificationEmailRequest request);
        Task ForgotPasswordAsync(ForgotPasswordRequest request);
        Task ResetPasswordAsync(ResetPasswordRequest request);
        Task LogoutAsync(string userId);
        Task<AuthResponse> ExternalLoginAsync(ExternalLoginRequest request);
        Task<bool> CheckEmailAvailabilityAsync(string email);
    }
}