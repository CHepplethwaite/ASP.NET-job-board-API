using backend.Core.DTOs.Auth;
using backend.Core.DTOs.User;
using backend.Core.Entities;
using backend.Core.Enums;
using backend.Core.Interfaces.Services;
using backend.Infrastructure.Data;
using Core.Exceptions;
using Core.Interfaces.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace backend.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailService _emailService;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuthService> _logger;

        // User caching with Lazy<Task<T>> for cache stampede protection
        private readonly ConcurrentDictionary<string, Lazy<Task<CachedUserDto>>> _userLoadingTasks =
            new ConcurrentDictionary<string, Lazy<Task<CachedUserDto>>>();

        private async Task<CachedUserDto> GetUserByIdCachedAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId)) return null;

            var cacheKey = $"{USER_ID_CACHE_PREFIX}{userId}";

            // Check cache first (hot path)
            if (_cache.TryGetValue(cacheKey, out CachedUserDto cachedUser))
            {
                return cachedUser;
            }

            // Use Lazy<Task<T>> to prevent concurrent loads of the same user
            var loadingTask = _userLoadingTasks.GetOrAdd(cacheKey, _ =>
                new Lazy<Task<CachedUserDto>>(() => LoadAndCacheUserByIdAsync(userId, cacheKey)));

            try
            {
                return await loadingTask.Value;
            }
            finally
            {
                // Clean up completed task to prevent memory leak
                _userLoadingTasks.TryRemove(cacheKey, out _);
            }
        }

        private async Task<CachedUserDto> LoadAndCacheUserByIdAsync(string userId, string cacheKey)
        {
            var user = await _userManager.FindByIdAsync(userId);

            // Don't cache inactive users
            if (user == null || !user.IsActive)
            {
                // Cache null results briefly to reduce database pressure
                var nullOptions = new MemoryCacheEntryOptions()
                    .SetAbsoluteExpiration(TimeSpan.FromSeconds(30))
                    .SetSize(1); // Track size for MemoryCache eviction

                _cache.Set(cacheKey, null, nullOptions);
                return null;
            }

            var cachedUser = MapToCachedUserDto(user);
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(CACHE_TTL_MINUTES))
                .SetSize(1);

            _cache.Set(cacheKey, cachedUser, cacheOptions);

            // Also cache by email for FindByEmailAsync
            var emailCacheKey = $"{USER_EMAIL_CACHE_PREFIX}{HashEmail(user.Email)}";
            _cache.Set(emailCacheKey, cachedUser, cacheOptions);

            return cachedUser;
        }

        private async Task<CachedUserDto> GetUserByEmailCachedAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) return null;

            var cacheKey = $"{USER_EMAIL_CACHE_PREFIX}{HashEmail(email)}";

            if (_cache.TryGetValue(cacheKey, out CachedUserDto cachedUser))
            {
                return cachedUser;
            }

            // Fall back to database lookup
            var user = await _userManager.FindByEmailAsync(email);

            // Don't cache inactive users
            if (user == null || !user.IsActive)
            {
                var nullOptions = new MemoryCacheEntryOptions()
                    .SetAbsoluteExpiration(TimeSpan.FromSeconds(30))
                    .SetSize(1);

                _cache.Set(cacheKey, null, nullOptions);
                return null;
            }

            cachedUser = MapToCachedUserDto(user);
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(CACHE_TTL_MINUTES))
                .SetSize(1);

            _cache.Set(cacheKey, cachedUser, cacheOptions);

            return cachedUser;
        }

        // Token validation caching - simple and safe
        private async Task<ClaimsPrincipal> ValidateTokenWithCachingAsync(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
            {
                return null;
            }

            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

            // Require jti claim for caching (prevents caching tokens without unique identifiers)
            if (string.IsNullOrEmpty(jti))
            {
                return await ValidateTokenWithoutCacheAsync(token);
            }

            var cacheKey = $"{TOKEN_VALIDATION_CACHE_PREFIX}{jti}";

            if (_cache.TryGetValue(cacheKey, out ClaimsPrincipal cachedPrincipal))
            {
                return cachedPrincipal;
            }

            var principal = await ValidateTokenWithoutCacheAsync(token);

            // Only cache successful validations of access tokens
            if (principal?.Identity?.IsAuthenticated == true)
            {
                // Never cache refresh tokens
                var tokenType = principal.FindFirst("token_type")?.Value;
                if (tokenType != "refresh")
                {
                    // Short sliding window with absolute cap
                    var cacheOptions = new MemoryCacheEntryOptions()
                        .SetSlidingExpiration(TimeSpan.FromSeconds(45))
                        .SetAbsoluteExpiration(TimeSpan.FromMinutes(2))
                        .SetSize(1);

                    _cache.Set(cacheKey, principal, cacheOptions);
                }
            }

            return principal;
        }

        // Email hashing for cache keys (deterministic and collision-safe)
        private string HashEmail(string email)
        {
            using var sha256 = SHA256.Create();
            var normalizedEmail = email.ToLowerInvariant().Trim();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(normalizedEmail));
            return Convert.ToBase64String(hashBytes);
        }

        // Simple cache invalidation methods (no background services needed)
        public void InvalidateUserCache(string userId, string email)
        {
            if (!string.IsNullOrEmpty(userId))
            {
                _cache.Remove($"{USER_ID_CACHE_PREFIX}{userId}");
                _userLoadingTasks.TryRemove($"{USER_ID_CACHE_PREFIX}{userId}", out _);
            }

            if (!string.IsNullOrEmpty(email))
            {
                _cache.Remove($"{USER_EMAIL_CACHE_PREFIX}{HashEmail(email)}");
            }
        }

        public void InvalidateTokenCache(string jti)
        {
            if (!string.IsNullOrEmpty(jti))
            {
                _cache.Remove($"{TOKEN_VALIDATION_CACHE_PREFIX}{jti}");
            }
        }

        // Issue #8: Implement Basic Caching
        // TODO: Add IMemoryCache or IDistributedCache dependency
        // private readonly IMemoryCache _cache;

        // Issue #1: Implement Rate Limiting
        // TODO: Add rate limiting service/dependency
        // private readonly IRateLimiter _rateLimiter;

        // Issue #6: Prevent Concurrent Refresh Token Race Condition
        // TODO: Add synchronization primitive for refresh token operations
        // private readonly SemaphoreSlim _refreshTokenLock = new SemaphoreSlim(1, 1);

        public AuthService(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            IEmailService emailService,
            ApplicationDbContext context,
            ILogger<AuthService> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _context = context;
            _logger = logger;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            // Issue #2: Fix Email Enumeration Vulnerability
            // TODO: Consider removing explicit email check or handle in a way that prevents timing attacks
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
            var roleResult = await _userManager.AddToRoleAsync(user, request.UserType);
            if (!roleResult.Succeeded)
            {
                // Clean up user if role assignment fails
                await _userManager.DeleteAsync(user);
                throw new ValidationException(string.Join(", ", roleResult.Errors.Select(e => e.Description)));
            }

            // Create profile based on user type
            await CreateUserProfileAsync(user);

            // Issue #4: Remove Email from Database Transactions
            // TODO: Move email sending outside transaction scope
            // Make it fire-and-forget with error handling
            try
            {
                // Generate email verification
                await SendVerificationEmailAsync(user);
            }
            catch (Exception ex)
            {
                // Issue #7: Add Email Retry Mechanism
                // TODO: Implement retry with exponential backoff
                // TODO: Queue failed emails for retry
                // TODO: Log for manual intervention
                _logger.LogError(ex, "Failed to send verification email for user {UserId}, but registration succeeded", user.Id);
            }

            // Issue #8: Implement Basic Caching
            // TODO: Add user to cache after creation
            // _cache.Set($"user_{user.Id}", user, TimeSpan.FromMinutes(5));

            // Sign in to generate proper claims
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Get authenticated user with claims
            var userPrincipal = await _signInManager.CreateUserPrincipalAsync(user);
            var token = GenerateTokenFromPrincipal(userPrincipal);

            _logger.LogInformation("User registered successfully: {UserId} ({Email})", user.Id, user.Email);

            return new AuthResponse
            {
                Token = token,
                TokenExpiry = DateTime.UtcNow.AddHours(1), // Standard JWT expiration
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            // Issue #1: Implement Rate Limiting
            // TODO: Check rate limit for IP/email before attempting login
            // if (await _rateLimiter.IsRateLimited($"login_{GetClientIp()}", 5, TimeSpan.FromMinutes(5)))
            // {
            //     throw new RateLimitException("Too many login attempts. Please try again later.");
            // }

            // TODO: Also check per-email rate limit

            var result = await _signInManager.PasswordSignInAsync(
                request.Email,
                request.Password,
                isPersistent: false,
                lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out: {Email}", request.Email);
                throw new AuthException("Account is locked. Please try again later or reset your password.");
            }

            if (!result.Succeeded)
            {
                // Issue #1: Implement Rate Limiting
                // TODO: Increment rate limit counter on failed login

                _logger.LogWarning("Login failed for email: {Email}", request.Email);
                throw new AuthException("Invalid credentials");
            }

            // Issue #8: Implement Basic Caching
            // TODO: Try to get user from cache first
            // if (!_cache.TryGetValue($"user_email_{request.Email}", out User user))
            // {
            //     user = await _userManager.FindByEmailAsync(request.Email);
            //     _cache.Set($"user_email_{request.Email}", user, TimeSpan.FromMinutes(5));
            // }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive)
            {
                await _signInManager.SignOutAsync();
                throw new AuthException("Invalid credentials");
            }

            // Update last login
            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Refresh sign-in to update security stamp claims
            await _signInManager.RefreshSignInAsync(user);

            // Get authenticated user with claims
            var userPrincipal = await _signInManager.CreateUserPrincipalAsync(user);
            var token = GenerateTokenFromPrincipal(userPrincipal);

            // Issue #1: Implement Rate Limiting
            // TODO: Reset rate limit on successful login

            _logger.LogInformation("User logged in successfully: {UserId}", user.Id);

            return new AuthResponse
            {
                Token = token,
                TokenExpiry = DateTime.UtcNow.AddHours(1),
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task<ExternalLoginInfo> GetExternalLoginInfoAsync()
        {
            return await _signInManager.GetExternalLoginInfoAsync();
        }

        public async Task<AuthResponse> ExternalLoginCallbackAsync(ExternalLoginInfo info)
        {
            // Issue #1: Implement Rate Limiting
            // TODO: Consider rate limiting for external login attempts

            // Sign in the user with this external login provider if they already have a login
            var result = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider,
                info.ProviderKey,
                isPersistent: false,
                bypassTwoFactor: true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (user != null && user.IsActive)
                {
                    await _signInManager.RefreshSignInAsync(user);
                    var userPrincipal = await _signInManager.CreateUserPrincipalAsync(user);
                    var token = GenerateTokenFromPrincipal(userPrincipal);

                    return new AuthResponse
                    {
                        Token = token,
                        TokenExpiry = DateTime.UtcNow.AddHours(1),
                        TokenType = "Bearer",
                        User = MapToUserDto(user)
                    };
                }
            }

            // If the user does not have an account, create one
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                throw new AuthException("External provider did not return an email address");
            }

            var userByEmail = await _userManager.FindByEmailAsync(email);
            if (userByEmail != null)
            {
                // User exists but hasn't linked this external login
                var addLoginResult = await _userManager.AddLoginAsync(userByEmail, info);
                if (!addLoginResult.Succeeded)
                {
                    throw new ValidationException(string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                }

                await _signInManager.SignInAsync(userByEmail, isPersistent: false);
                var userPrincipal = await _signInManager.CreateUserPrincipalAsync(userByEmail);
                var token = GenerateTokenFromPrincipal(userPrincipal);

                return new AuthResponse
                {
                    Token = token,
                    TokenExpiry = DateTime.UtcNow.AddHours(1),
                    TokenType = "Bearer",
                    User = MapToUserDto(userByEmail)
                };
            }

            // Create new user
            var user = new User
            {
                UserName = email,
                Email = email,
                FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? info.Principal.FindFirstValue(ClaimTypes.Name),
                LastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? string.Empty,
                UserType = UserType.JobSeeker, // Default for external login
                CreatedAt = DateTime.UtcNow,
                IsActive = true,
                EmailConfirmed = true, // External providers verify email
                ProfilePictureUrl = info.Principal.FindFirstValue("picture") // For Google profile picture
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                throw new ValidationException(string.Join(", ", createResult.Errors.Select(e => e.Description)));
            }

            // Add to default role
            await _userManager.AddToRoleAsync(user, UserType.JobSeeker.ToString());

            // Add external login
            var addResult = await _userManager.AddLoginAsync(user, info);
            if (!addResult.Succeeded)
            {
                await _userManager.DeleteAsync(user);
                throw new ValidationException(string.Join(", ", addResult.Errors.Select(e => e.Description)));
            }

            // Create profile
            await CreateUserProfileAsync(user);

            await _signInManager.SignInAsync(user, isPersistent: false);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var newToken = GenerateTokenFromPrincipal(principal);

            _logger.LogInformation("External user created: {UserId} ({Email})", user.Id, user.Email);

            return new AuthResponse
            {
                Token = newToken,
                TokenExpiry = DateTime.UtcNow.AddHours(1),
                TokenType = "Bearer",
                User = MapToUserDto(user)
            };
        }

        public async Task ChangePasswordAsync(string userId, ChangePasswordRequest request)
        {
            // Issue #8: Implement Basic Caching
            // TODO: Invalidate user cache after password change

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

            // Update security stamp to invalidate existing tokens
            await _userManager.UpdateSecurityStampAsync(user);

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Password changed for user: {UserId}", user.Id);
        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out successfully");
        }

        public async Task LogoutAllDevicesAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            // Update security stamp to invalidate all existing tokens
            await _userManager.UpdateSecurityStampAsync(user);

            _logger.LogInformation("All sessions terminated for user: {UserId}", user.Id);
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
            user.UpdatedAt = DateTime.UtcNow;

            // Update security stamp to invalidate existing sessions
            await _userManager.UpdateSecurityStampAsync(user);

            await _userManager.UpdateAsync(user);

            // Issue #8: Implement Basic Caching
            // TODO: Invalidate user cache after deactivation

            await _signInManager.SignOutAsync();

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

            // Issue #8: Implement Basic Caching
            // TODO: Update user in cache after reactivation

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

            var result = await _userManager.ConfirmEmailAsync(user, request.Token);
            if (!result.Succeeded)
            {
                throw new ValidationException("Invalid or expired verification token");
            }

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Issue #8: Implement Basic Caching
            // TODO: Update user in cache after email verification

            _logger.LogInformation("Email verified for user: {UserId} ({Email})", user.Id, user.Email);
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

            // Issue #7: Add Email Retry Mechanism
            // TODO: Implement retry with exponential backoff
            await SendVerificationEmailAsync(user);

            _logger.LogInformation("Verification email resent for user: {UserId} ({Email})", user.Id, user.Email);
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            // Issue #1: Implement Rate Limiting
            // TODO: Check rate limit for IP/email before sending reset email
            // if (await _rateLimiter.IsRateLimited($"reset_{GetClientIp()}", 3, TimeSpan.FromHours(1)))
            // {
            //     throw new RateLimitException("Too many password reset attempts. Please try again later.");
            // }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive || !user.EmailConfirmed)
            {
                // Don't reveal that user doesn't exist for security reasons
                _logger.LogWarning("Password reset requested for non-existent or inactive email: {Email}", request.Email);
                return;
            }

            // Issue #1: Implement Rate Limiting
            // TODO: Increment rate limit counter

            // Generate password reset token using Identity's token provider
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Issue #7: Add Email Retry Mechanism
            // TODO: Implement retry with exponential backoff
            // Send email
            await _emailService.SendPasswordResetEmailAsync(user.Email, user.FirstName, token);

            _logger.LogInformation("Password reset email sent for user: {UserId} ({Email})", user.Id, user.Email);
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            // Issue #1: Implement Rate Limiting
            // TODO: Consider rate limiting for reset attempts

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (!user.IsActive)
            {
                throw new ValidationException("User account is not active");
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (!result.Succeeded)
            {
                throw new ValidationException(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            // Update security stamp to invalidate existing sessions
            await _userManager.UpdateSecurityStampAsync(user);

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Password reset successful for user: {UserId} ({Email})", user.Id, user.Email);
        }

        public async Task<bool> CheckEmailAvailabilityAsync(string email)
        {
            // Issue #2: Fix Email Enumeration Vulnerability
            // TODO: Implement constant-time email check to prevent timing attacks
            // Options:
            // 1. Always delay response by fixed time (e.g., 500ms)
            // 2. Use cryptographic comparison
            // 3. Remove this method and handle in registration only

            // Current implementation (vulnerable to timing attacks):
            var user = await _userManager.FindByEmailAsync(email);
            return user == null;
        }

        public async Task<AuthResponse> RefreshTokenAsync(string refreshToken, string userId)
        {
            // Issue #3: Hash Refresh Tokens Before Storage
            // TODO: Implement refresh token hashing using SHA256
            // TODO: Store hashed tokens in cache (Redis/MemoryCache) instead of database
            // Example:
            // var hashedToken = SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken));
            // var storedTokenHash = await _cache.GetStringAsync($"refresh_{userId}");

            // Issue #5: Fix Refresh Token Null Check Bug
            // TODO: Add proper null check for stored token
            // if (string.IsNullOrEmpty(storedTokenHash))
            // {
            //     throw new AuthException("Invalid or expired refresh token");
            // }

            // TODO: Compare hashes using constant-time comparison

            // Issue #6: Prevent Concurrent Refresh Token Race Condition
            // TODO: Implement lock mechanism to prevent race conditions
            // await _refreshTokenLock.WaitAsync();
            // try
            // {
            //     // Refresh token logic here
            // }
            // finally
            // {
            //     _refreshTokenLock.Release();
            // }

            throw new NotImplementedException("Refresh token functionality not yet implemented");
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

        private async Task SendVerificationEmailAsync(User user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Issue #7: Add Email Retry Mechanism
            // TODO: Implement retry with exponential backoff
            // Send email using Identity's token
            await _emailService.SendVerificationEmailAsync(user.Email, user.FirstName, token);
        }

        private string GenerateTokenFromPrincipal(ClaimsPrincipal principal)
        {
            // Issue #8: Implement Basic Caching
            // TODO: Consider caching token validation results for 1 minute

            // This would be replaced with your actual JWT generation logic
            // that uses the claims from the Identity principal
            // For now, returning a placeholder

            // In production, you would use:
            // var tokenHandler = new JwtSecurityTokenHandler();
            // var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);
            // var tokenDescriptor = new SecurityTokenDescriptor
            // {
            //     Subject = new ClaimsIdentity(principal.Claims),
            //     Expires = DateTime.UtcNow.AddHours(1),
            //     SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            // };
            // var token = tokenHandler.CreateToken(tokenDescriptor);
            // return tokenHandler.WriteToken(token);

            // Note: Make sure to include the security stamp claim for automatic invalidation
            // principal.Claims.Append(new Claim("AspNet.Identity.SecurityStamp", await _userManager.GetSecurityStampAsync(user)));

            return "jwt-token-placeholder"; // Replace with actual JWT generation
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

        // Issue #9: Add Database Indexes
        // TODO: Ensure database has indexes on:
        // - Users.Email column (for fast lookups)
        // - Users.RefreshToken column (if storing in DB)
        // This is a database concern, not code, but we should add migration for it
    }
}