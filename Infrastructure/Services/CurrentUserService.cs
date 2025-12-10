using System.Security.Claims;
using Core.Interfaces.Services;
using Microsoft.AspNetCore.Http;

namespace Infrastructure.Services;

public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid? UserId
    {
        get
        {
            var userIdClaim = _httpContextAccessor.HttpContext?.User?
                .FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (Guid.TryParse(userIdClaim, out var userId))
                return userId;

            return null;
        }
    }

    public string? Email => _httpContextAccessor.HttpContext?.User?
        .FindFirst(ClaimTypes.Email)?.Value;

    public bool IsAuthenticated => UserId.HasValue;

    public async Task<bool> IsInRoleAsync(string role)
    {
        return _httpContextAccessor.HttpContext?.User?
            .IsInRole(role) ?? false;
    }

    public async Task<IList<string>> GetRolesAsync()
    {
        return _httpContextAccessor.HttpContext?.User?
            .FindAll(ClaimTypes.Role)
            .Select(c => c.Value)
            .ToList() ?? new List<string>();
    }
}