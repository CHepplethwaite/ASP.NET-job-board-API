using System.Security.Claims;
using backend.Core.Entities;

namespace backend.Core.Interfaces.Services
{
    public interface ITokenService
    {
        string GenerateJwtToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        Task<User?> GetUserFromTokenAsync(string token);
    }
}