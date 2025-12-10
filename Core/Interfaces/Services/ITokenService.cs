using Core.Entities;

namespace Core.Interfaces.Services;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    string GenerateRefreshToken();
    Task<string> GenerateEmailVerificationCodeAsync(Guid userId);
    Task<bool> ValidateEmailVerificationCodeAsync(Guid userId, string code);
    Task<string> GeneratePasswordResetTokenAsync(Guid userId);
    Task<bool> ValidatePasswordResetTokenAsync(string token);
    Guid? GetUserIdFromExpiredToken(string token);
}