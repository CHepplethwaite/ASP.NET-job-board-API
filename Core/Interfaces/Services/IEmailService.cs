namespace Core.Interfaces.Services;

public interface IEmailService
{
    Task SendEmailVerificationAsync(string email, string verificationCode, string name);
    Task SendPasswordResetEmailAsync(string email, string resetToken, string name);
    Task SendWelcomeEmailAsync(string email, string name);
}