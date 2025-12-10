namespace Infrastructure.Security;

public class JwtSettings
{
    public string Secret { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public int AccessTokenExpirationMinutes { get; set; } = 60;
    public int RefreshTokenExpirationDays { get; set; } = 7;
    public int EmailVerificationCodeExpirationMinutes { get; set; } = 15;
    public int PasswordResetTokenExpirationMinutes { get; set; } = 30;
}