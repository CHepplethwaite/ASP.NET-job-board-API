using Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;

namespace Infrastructure.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendEmailVerificationAsync(string email, string verificationCode, string name)
    {
        var subject = "Verify Your Email - JobBoard";
        var body = $@"
            <h1>Welcome to JobBoard, {name}!</h1>
            <p>Please use the following code to verify your email address:</p>
            <h2 style='background-color: #f4f4f4; padding: 10px; text-align: center; letter-spacing: 5px;'>
                {verificationCode}
            </h2>
            <p>This code will expire in 15 minutes.</p>
            <p>If you didn't create an account, please ignore this email.</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendPasswordResetEmailAsync(string email, string resetToken, string name)
    {
        var resetUrl = $"{_configuration["App:BaseUrl"]}/reset-password?token={resetToken}";
        var subject = "Reset Your Password - JobBoard";
        var body = $@"
            <h1>Password Reset Request</h1>
            <p>Hello {name},</p>
            <p>You have requested to reset your password. Click the link below to proceed:</p>
            <p><a href='{resetUrl}' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>
                Reset Password
            </a></p>
            <p>Or copy and paste this link: {resetUrl}</p>
            <p>This link will expire in 30 minutes.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendWelcomeEmailAsync(string email, string name)
    {
        var subject = "Welcome to JobBoard!";
        var body = $@"
            <h1>Welcome to JobBoard, {name}!</h1>
            <p>Thank you for joining our job board platform. We're excited to have you on board!</p>
            <p>With JobBoard, you can:</p>
            <ul>
                <li>Search for thousands of job opportunities</li>
                <li>Connect with top employers</li>
                <li>Create and manage your professional profile</li>
                <li>Get personalized job recommendations</li>
            </ul>
            <p>Please verify your email address to unlock all features.</p>
            <p>If you have any questions, feel free to contact our support team.</p>
            <p>Best regards,<br>The JobBoard Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    private async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        try
        {
            var apiKey = _configuration["SendGrid:ApiKey"];
            var fromEmail = _configuration["SendGrid:FromEmail"];
            var fromName = _configuration["SendGrid:FromName"];

            if (string.IsNullOrEmpty(apiKey))
            {
                _logger.LogWarning("SendGrid API key not configured. Email would be sent to: {ToEmail}", toEmail);
                _logger.LogInformation("Email content - Subject: {Subject}, Body: {Body}", subject, body);
                return;
            }

            var client = new SendGridClient(apiKey);
            var from = new EmailAddress(fromEmail, fromName);
            var to = new EmailAddress(toEmail);
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, body);

            var response = await client.SendEmailAsync(msg);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to send email. Status: {StatusCode}, Body: {Body}",
                    response.StatusCode, await response.Body.ReadAsStringAsync());
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email to {Email}", toEmail);
        }
    }
}