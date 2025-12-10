using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Core.Entities;
using Core.Interfaces.Services;
using Infrastructure.Data;
using Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Services;

public class TokenService : ITokenService
{
    private readonly JwtSettings _jwtSettings;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<TokenService> _logger;

    public TokenService(
        IOptions<JwtSettings> jwtSettings,
        ApplicationDbContext context,
        ILogger<TokenService> logger)
    {
        _jwtSettings = jwtSettings.Value;
        _context = context;
        _logger = logger;
    }

    public string GenerateAccessToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Name, user.FullName)
        };

        // Add roles as claims
        var roles = _context.UserRoles
            .Where(ur => ur.UserId == user.Id)
            .Include(ur => ur.Role)
            .Select(ur => ur.Role.Name)
            .ToList();

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public async Task<string> GenerateEmailVerificationCodeAsync(Guid userId)
    {
        // Generate 6-character alphanumeric code
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var random = new Random();
        var code = new string(Enumerable.Repeat(chars, 6)
            .Select(s => s[random.Next(s.Length)]).ToArray());

        var verificationCode = new EmailVerificationCode
        {
            UserId = userId,
            Code = code,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.EmailVerificationCodeExpirationMinutes)
        };

        await _context.EmailVerificationCodes.AddAsync(verificationCode);
        await _context.SaveChangesAsync();

        return code;
    }

    public async Task<bool> ValidateEmailVerificationCodeAsync(Guid userId, string code)
    {
        var verificationCode = await _context.EmailVerificationCodes
            .Where(evc => evc.UserId == userId && evc.Code == code && !evc.IsUsed)
            .OrderByDescending(evc => evc.CreatedAt)
            .FirstOrDefaultAsync();

        if (verificationCode == null || verificationCode.IsExpired)
            return false;

        verificationCode.VerifiedAt = DateTime.UtcNow;
        _context.EmailVerificationCodes.Update(verificationCode);
        await _context.SaveChangesAsync();

        return true;
    }

    public async Task<string> GeneratePasswordResetTokenAsync(Guid userId)
    {
        var token = GenerateRefreshToken(); // Reuse refresh token generation
        var expiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.PasswordResetTokenExpirationMinutes);

        // In a real implementation, you'd store this token in the database
        // For simplicity, we'll use JWT for password reset
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim("purpose", "password-reset"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = expiresAt,
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(securityToken);
    }

    public async Task<bool> ValidatePasswordResetTokenAsync(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            var purpose = principal.FindFirst("purpose")?.Value;

            return purpose == "password-reset";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating password reset token");
            return false;
        }
    }

    public Guid? GetUserIdFromExpiredToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false // Allow expired tokens for refresh
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            if (Guid.TryParse(userIdClaim, out var userId))
                return userId;

            return null;
        }
        catch
        {
            return null;
        }
    }
}