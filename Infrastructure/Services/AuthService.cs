using backend.Core.DTOs.Auth;
using backend.Core.DTOs.User;
using backend.Core.Entities;
using backend.Core.Enums;
using backend.Core.Interfaces.Services;
using backend.Infrastructure.Data;
using Core.Exceptions;
using Core.Interfaces.Services;
using Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security;
using System.Security.Claims;
using System.Text;

namespace backend.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly ApplicationDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ITokenService tokenService,
            IEmailService emailService,
            ApplicationDbContext context,
            IOptions<JwtSettings> jwtSettings,
            ILogger<AuthService> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _emailService = emailService;
            _context = context;
            _jwtSettings = jwtSettings.Value;
            _logger = logger;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            // Check if user exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                throw new ValidationException("User with this email already exists");
            }

            // Validate UserType
            if (!Enum.TryParse<UserType>(request.UserType, true, out var userType))
            {
                throw new ValidationException("Invalid user type. Must be JobSeeker, Recruiter, or Company");
            }

            // Create user
            var user = new User
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber,
                CompanyName = request.CompanyName,
                UserType = userType,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                throw new ValidationException(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            // Add to role
            await _userManager.AddToRoleAsync(user, request.UserType);

            // Create profile based on user type
            await CreateUserProfileAsync(user);

            // Generate email verification
            await GenerateAndSendVerificationEmailAsync(user);

            // Generate tokens
            var token = _tokenService.GenerateJwtToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User registered successfully: {UserId} ({Email})", user.Id, user.Email);

            return new AuthResponse
            {
                Token = token,
                RefreshToken = refreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes),
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive)
            {
                _logger.LogWarning("Login failed for email: {Email} - User not found or inactive", request.Email);
                throw new AuthException("Invalid credentials");
            }

            // Enable lockout on failure
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out: {UserId}", user.Id);
                throw new AuthException("Account is locked. Please try again later or reset your password.");
            }

            if (!result.Succeeded)
            {
                _logger.LogWarning("Login failed for user: {UserId} - Invalid password", user.Id);
                throw new AuthException("Invalid credentials");
            }

            // Update last login
            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Generate tokens
            var token = _tokenService.GenerateJwtToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged in successfully: {UserId}", user.Id);

            return new AuthResponse
            {
                Token = token,
                RefreshToken = refreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes),
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(request.Token);
            if (principal == null)
            {
                throw new AuthException("Invalid token");
            }

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                throw new AuthException("User not found");
            }

            // Refresh token reuse detection
            if (user.RefreshToken != request.RefreshToken)
            {
                // If token doesn't match, possible theft - invalidate all tokens
                _logger.LogWarning("Refresh token reuse detected for user: {UserId}", user.Id);
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);
                throw new SecurityException("Refresh token reuse detected. Please login again.");
            }

            if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                throw new AuthException("Refresh token expired");
            }

            var newToken = _tokenService.GenerateJwtToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Token refreshed for user: {UserId}", user.Id);

            return new TokenResponse
            {
                Token = newToken,
                RefreshToken = newRefreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes),
                TokenType = "Bearer"
            };
        }

        public async Task ChangePasswordAsync(string userId, ChangePasswordRequest request)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (!user.IsActive)
            {
                throw new ValidationException("User account is not active");
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                throw new ValidationException(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            user.UpdatedAt = DateTime.UtcNow;

            // Invalidate all refresh tokens (security best practice)
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Password changed for user: {UserId}", user.Id);
        }

        public async Task LogoutAsync(LogoutRequest request)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
            {
                throw new ValidationException("Refresh token is required");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
            if (user == null)
            {
                _logger.LogWarning("Logout attempted with invalid refresh token");
                return; // Silent fail for security
            }

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged out successfully: {UserId}", user.Id);
        }

        public async Task<LogoutResult> LogoutAllDevicesAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            var hadToken = !string.IsNullOrEmpty(user.RefreshToken);

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("All sessions terminated for user: {UserId}", user.Id);

            return new LogoutResult
            {
                Success = true,
                SessionsTerminated = hadToken ? 1 : 0,
                Message = "All active sessions have been terminated"
            };
        }

        public async Task DeactivateAccountAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (!user.IsActive)
            {
                throw new ValidationException("Account is already deactivated");
            }

            user.IsActive = false;
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            user.UpdatedAt = DateTime.UtcNow;

            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Account deactivated for user: {UserId}", user.Id);
        }

        public async Task ReactivateAccountAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (user.IsActive)
            {
                throw new ValidationException("Account is already active");
            }

            user.IsActive = true;
            user.UpdatedAt = DateTime.UtcNow;

            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Account reactivated for user: {UserId}", user.Id);
        }

        public async Task VerifyEmailAsync(VerifyEmailRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (user.EmailConfirmed)
            {
                throw new ValidationException("Email is already verified");
            }

            try
            {
                // Decode the token
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));

                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
                if (!result.Succeeded)
                {
                    throw new ValidationException("Invalid or expired verification token");
                }

                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                _logger.LogInformation("Email verified for user: {UserId} ({Email})", user.Id, user.Email);
            }
            catch (FormatException)
            {
                throw new ValidationException("Invalid token format");
            }
        }

        public async Task ResendVerificationEmailAsync(ResendVerificationEmailRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Don't reveal that user doesn't exist for security reasons
                _logger.LogWarning("Resend verification email requested for non-existent email: {Email}", request.Email);
                return;
            }

            if (user.EmailConfirmed)
            {
                throw new ValidationException("Email is already verified");
            }

            await GenerateAndSendVerificationEmailAsync(user);

            _logger.LogInformation("Verification email resent for user: {UserId} ({Email})", user.Id, user.Email);
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive)
            {
                // Don't reveal that user doesn't exist for security reasons
                _logger.LogWarning("Password reset requested for non-existent or inactive email: {Email}", request.Email);
                return;
            }

            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            // Send email
            await _emailService.SendPasswordResetEmailAsync(user.Email, user.FirstName, encodedToken);

            _logger.LogInformation("Password reset email sent for user: {UserId} ({Email})", user.Id, user.Email);
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (!user.IsActive)
            {
                throw new ValidationException("User account is not active");
            }

            try
            {
                // Decode the token
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));

                var result = await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);
                if (!result.Succeeded)
                {
                    throw new ValidationException(string.Join(", ", result.Errors.Select(e => e.Description)));
                }

                user.UpdatedAt = DateTime.UtcNow;

                // Invalidate all active sessions
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                _logger.LogInformation("Password reset successful for user: {UserId} ({Email})", user.Id, user.Email);
            }
            catch (FormatException)
            {
                throw new ValidationException("Invalid token format");
            }
        }

        public async Task<AuthResponse> ExternalLoginAsync(ExternalLoginRequest request)
        {
            // Check if user already exists with this email
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                // Create new user
                user = new User
                {
                    UserName = request.Email,
                    Email = request.Email,
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    UserType = UserType.JobSeeker, // Default for external login
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true,
                    EmailConfirmed = true, // External providers verify email
                    ProfilePictureUrl = request.ProfilePictureUrl
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    throw new ValidationException(string.Join(", ", createResult.Errors.Select(e => e.Description)));
                }

                // Add to default role
                await _userManager.AddToRoleAsync(user, UserType.JobSeeker.ToString());

                // Create profile
                await CreateUserProfileAsync(user);

                _logger.LogInformation("External user created: {UserId} ({Email})", user.Id, user.Email);
            }
            else if (!user.IsActive)
            {
                throw new AuthException("User account is not active");
            }

            // Update last login
            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Generate tokens
            var token = _tokenService.GenerateJwtToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("External login successful for user: {UserId}", user.Id);

            return new AuthResponse
            {
                Token = token,
                RefreshToken = refreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes),
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task<bool> CheckEmailAvailabilityAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return user == null;
        }

        private async Task CreateUserProfileAsync(User user)
        {
            switch (user.UserType)
            {
                case UserType.JobSeeker:
                    var jobSeekerProfile = new JobSeekerProfile
                    {
                        UserId = user.Id,
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.JobSeekerProfiles.Add(jobSeekerProfile);
                    break;

                case UserType.Recruiter:
                    var recruiterProfile = new RecruiterProfile
                    {
                        UserId = user.Id,
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.RecruiterProfiles.Add(recruiterProfile);
                    break;

                case UserType.Company:
                    var companyProfile = new CompanyProfile
                    {
                        UserId = user.Id,
                        Name = user.CompanyName ?? $"{user.FirstName} {user.LastName}'s Company",
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.CompanyProfiles.Add(companyProfile);
                    break;
            }

            await _context.SaveChangesAsync();
        }

        private async Task GenerateAndSendVerificationEmailAsync(User user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            // Send email
            await _emailService.SendVerificationEmailAsync(user.Email, user.FirstName, encodedToken);
        }

        private UserDto MapToUserDto(User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                UserType = user.UserType.ToString(),
                EmailVerified = user.EmailConfirmed,
                ProfilePictureUrl = user.ProfilePictureUrl,
                CompanyName = user.CompanyName,
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };
        }
    }
}