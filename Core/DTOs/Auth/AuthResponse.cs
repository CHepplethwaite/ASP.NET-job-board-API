using backend.Core.DTOs.User;
using Core.DTOs.User;

namespace Core.DTOs.Auth;

public class AuthResponse
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public DateTime ExpiresAt { get; set; }
    public UserDto User { get; set; } = null!;
}