// IAuthService.cs
using backend.Core.DTOs.Auth;
using backend.Core.DTOs.User;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace backend.Core.Interfaces.Services
{
    public interface IAuthService
    {
        // Issue #1: Implement Rate Limiting
        // TODO: Add rate limiting decorators/attributes to login and password reset endpoints
        // Login endpoint: 5 attempts per 5 minutes per IP
        // Password reset endpoint: 3 attempts per hour per IP
        // Return 429 status code when limit exceeded

        Task<AuthResponse> RegisterAsync(RegisterRequest request);

        Task<AuthResponse> LoginAsync(LoginRequest request);

        Task<ExternalLoginInfo> GetExternalLoginInfoAsync();

        Task<AuthResponse> ExternalLoginCallbackAsync(ExternalLoginInfo info);

        Task ChangePasswordAsync(string userId, ChangePasswordRequest request);

        Task LogoutAsync();

        Task LogoutAllDevicesAsync(string userId);

        Task DeactivateAccountAsync(string userId);

        Task ReactivateAccountAsync(string userId);

        Task VerifyEmailAsync(VerifyEmailRequest request);

        Task ResendVerificationEmailAsync(ResendVerificationEmailRequest request);

        // Issue #1: Implement Rate Limiting
        // TODO: Apply rate limiting to forgot password endpoint
        Task ForgotPasswordAsync(ForgotPasswordRequest request);

        // Issue #1: Implement Rate Limiting
        // TODO: Apply rate limiting to reset password endpoint
        Task ResetPasswordAsync(ResetPasswordRequest request);

        // Issue #2: Fix Email Enumeration Vulnerability
        // TODO: Modify to prevent email enumeration
        // Options: 
        // 1. Remove this endpoint and handle in registration flow only
        // 2. Change to "registration availability check" with constant response time
        // 3. Return generic success/failure without revealing existence
        Task<bool> CheckEmailAvailabilityAsync(string email);

        // Issue #3: Hash Refresh Tokens Before Storage
        // TODO: Implement refresh token flow with hashed storage
        // Store in cache (Redis/MemoryCache) instead of database
        // Hash tokens using SHA256 before storage
        Task<AuthResponse> RefreshTokenAsync(string refreshToken, string userId);

        // Issue #5: Fix Refresh Token Null Check Bug
        // TODO: Ensure proper null checks in refresh token validation

        // Issue #6: Prevent Concurrent Refresh Token Race Condition
        // TODO: Add lock mechanism for concurrent refresh requests
        // Consider using distributed lock for multi-instance deployments

        // Issue #8: Implement Basic Caching
        // TODO: Add caching decorators/implementation for:
        // - User lookups (5 minute TTL)
        // - Token validation results (1 minute TTL)
        // TODO: Add cache invalidation on user updates

        // Helper method for token generation (used internally)
        string GenerateTokenFromPrincipal(ClaimsPrincipal principal);
    }
}