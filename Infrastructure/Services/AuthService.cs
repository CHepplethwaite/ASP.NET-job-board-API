using Core.DTOs.Auth;
using Core.DTOs.User;
using Core.Entities;
using Core.Enums;
using Core.Exceptions;
using Core.Interfaces.Repositories;
using Core.Interfaces.Services;
using Infrastructure.Security;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IUnitOfWork unitOfWork,
        ITokenService tokenService,
        IEmailService emailService,
        IPasswordHasher passwordHasher,
        ILogger<AuthService> logger)
    {
        _unitOfWork = unitOfWork;
        _tokenService = tokenService;
        _emailService = emailService;
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        // Validate email availability
        if (await _unitOfWork.Users.ExistsByEmailAsync(request.Email))
            throw new AuthException("Email is already registered");

        // Validate role
        var roleId = request.Role.ToLower() switch
        {
            "recruiter" => 2,
            "jobseeker" => 3,
            _ => throw new ValidationException(new Dictionary<string, string[]>
            {
                { "Role", new[] { "Invalid role. Must be 'Recruiter' or 'JobSeeker'" } }
            })
        };

        var user = new User
        {
            Email = request.Email,
            NormalizedEmail = request.Email.ToUpper(),
            FirstName = request.FirstName,
            LastName = request.LastName,
            PasswordHash = _passwordHasher.HashPassword(request.Password),
            CompanyName = request.CompanyName,
            JobTitle = request.JobTitle,
            PhoneNumber = request.PhoneNumber,
            AuthProvider = AuthProvider.Local
        };

        await _unitOfWork.BeginTransactionAsync();

        try
        {
            await _unitOfWork.Users.AddAsync(user);
            await _unitOfWork.CompleteAsync();

            await _unitOfWork.Users.AddUserRoleAsync(user.Id, roleId);
            await _unitOfWork.CompleteAsync();

            // Generate email verification code
            var verificationCode = await _tokenService.GenerateEmailVerificationCodeAsync(user.Id);

            // Send welcome email with verification code
            await _emailService.SendWelcomeEmailAsync(user.Email, user.FullName);
            await _emailService.SendEmailVerificationAsync(user.Email, verificationCode, user.FullName);

            await _unitOfWork.CommitTransactionAsync();

            // Generate tokens
            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Save refresh token
            await SaveRefreshTokenAsync(user.Id, refreshToken);

            return new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                User = MapToUserDto(user, new List<string> { request.Role })
            };
        }
        catch (Exception)
        {
            await _unitOfWork.RollbackTransactionAsync();
            throw;
        }
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await _unitOfWork.Users.GetByEmailWithRolesAsync(request.Email);

        if (user == null || user.AuthProvider != AuthProvider.Local)
            throw new AuthException("Invalid email or password");

        if (user.IsBanned)
            throw new AuthException("Account is banned. Please contact support.");

        if (!user.IsActive)
            throw new AuthException("Account is inactive. Please contact support.");

        if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash!))
            throw new AuthException("Invalid email or password");

        // Update last login
        user.LastLoginAt = DateTime.UtcNow;
        await _unitOfWork.Users.UpdateAsync(user);
        await _unitOfWork.CompleteAsync();

        // Get user roles
        var roles = await _unitOfWork.Users.GetUserRolesAsync(user.Id);

        // Generate tokens
        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Save refresh token
        await SaveRefreshTokenAsync(user.Id, refreshToken);

        return new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            User = MapToUserDto(user, roles.ToList())
        };
    }

    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        // Get the token from database
        var token = await GetRefreshTokenAsync(refreshToken);

        if (token == null || !token.IsActive)
            throw new AuthException("Invalid refresh token");

        // Revoke current token
        token.RevokedAt = DateTime.UtcNow;
        await _unitOfWork.CompleteAsync();

        var user = await _unitOfWork.Users.GetByIdAsync(token.UserId);
        if (user == null || !user.IsActive || user.IsBanned)
            throw new AuthException("User not found or inactive");

        // Generate new tokens
        var newAccessToken = _tokenService.GenerateAccessToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        // Save new refresh token
        await SaveRefreshTokenAsync(user.Id, newRefreshToken);

        var roles = await _unitOfWork.Users.GetUserRolesAsync(user.Id);

        return new AuthResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            User = MapToUserDto(user, roles.ToList())
        };
    }

    public async Task VerifyEmailAsync(VerifyEmailRequest request)
    {
        var user = await _unitOfWork.Users.GetByEmailAsync(request.Email);

        if (user == null)
            throw new NotFoundException("User not found");

        if (user.IsEmailVerified)
            throw new AuthException("Email is already verified");

        var isValid = await _tokenService.ValidateEmailVerificationCodeAsync(user.Id, request.Code);

        if (!isValid)
            throw new AuthException("Invalid or expired verification code");

        user.IsEmailVerified = true;
        user.EmailVerifiedAt = DateTime.UtcNow;

        await _unitOfWork.Users.UpdateAsync(user);
        await _unitOfWork.CompleteAsync();
    }

    public async Task SendVerificationEmailAsync(string email)
    {
        var user = await _unitOfWork.Users.GetByEmailAsync(email);

        if (user == null)
            throw new NotFoundException("User not found");

        if (user.IsEmailVerified)
            throw new AuthException("Email is already verified");

        var verificationCode = await _tokenService.GenerateEmailVerificationCodeAsync(user.Id);
        await _emailService.SendEmailVerificationAsync(email, verificationCode, user.FullName);
    }

    public async Task SendPasswordResetEmailAsync(ForgotPasswordRequest request)
    {
        var user = await _unitOfWork.Users.GetByEmailAsync(request.Email);

        if (user == null || user.AuthProvider != AuthProvider.Local)
            return; // Don't reveal if user exists

        var resetToken = await _tokenService.GeneratePasswordResetTokenAsync(user.Id);
        await _emailService.SendPasswordResetEmailAsync(user.Email, resetToken, user.FullName);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest request)
    {
        var userId = _tokenService.GetUserIdFromExpiredToken(request.Token);

        if (userId == null)
            throw new AuthException("Invalid or expired reset token");

        var isValid = await _tokenService.ValidatePasswordResetTokenAsync(request.Token);

        if (!isValid)
            throw new AuthException("Invalid or expired reset token");

        var user = await _unitOfWork.Users.GetByIdAsync(userId.Value);

        if (user == null || user.AuthProvider != AuthProvider.Local)
            throw new NotFoundException("User not found");

        user.PasswordHash = _passwordHasher.HashPassword(request.NewPassword);
        user.UpdatedAt = DateTime.UtcNow;

        await _unitOfWork.Users.UpdateAsync(user);
        await _unitOfWork.CompleteAsync();
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken)
    {
        var token = await GetRefreshTokenAsync(refreshToken);

        if (token == null || token.IsRevoked)
            return;

        token.RevokedAt = DateTime.UtcNow;
        await _unitOfWork.CompleteAsync();
    }

    public async Task<bool> IsEmailAvailableAsync(string email)
    {
        return !await _unitOfWork.Users.ExistsByEmailAsync(email);
    }

    public Task<AuthResponse> ExternalLoginAsync(string provider, string idToken) // Pending implementation
    {
        return Task.FromException<AuthResponse>(
            new NotImplementedException("External login implementation depends on OAuth provider configuration")
        );
    }


    private async Task SaveRefreshTokenAsync(Guid userId, string refreshToken)
    {
        var token = new RefreshToken
        {
            UserId = userId,
            Token = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow
        };

        await _unitOfWork.CompleteAsync();
    }

    private Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        // Implement based on your database context
        throw new NotImplementedException();
    }

    private UserDto MapToUserDto(User user, List<string> roles)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            ProfilePictureUrl = user.ProfilePictureUrl,
            PhoneNumber = user.PhoneNumber,
            CompanyName = user.CompanyName,
            JobTitle = user.JobTitle,
            IsEmailVerified = user.IsEmailVerified,
            CreatedAt = user.CreatedAt,
            Roles = roles
        };
    }
}