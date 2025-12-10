using Core.Entities;

namespace Core.Interfaces.Repositories;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id);
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByEmailWithRolesAsync(string email);
    Task<IEnumerable<User>> GetAllAsync(int page, int pageSize);
    Task AddAsync(User user);
    Task UpdateAsync(User user);
    Task DeleteAsync(User user);
    Task<bool> ExistsByEmailAsync(string email);
    Task AddUserRoleAsync(Guid userId, int roleId);
    Task RemoveUserRoleAsync(Guid userId, int roleId);
    Task<IEnumerable<string>> GetUserRolesAsync(Guid userId);
    Task<bool> IsInRoleAsync(Guid userId, string role);
}