namespace Core.Interfaces.Services;

public interface ICurrentUserService
{
    Guid? UserId { get; }
    string? Email { get; }
    bool IsAuthenticated { get; }
    Task<bool> IsInRoleAsync(string role);
    Task<IList<string>> GetRolesAsync();
}