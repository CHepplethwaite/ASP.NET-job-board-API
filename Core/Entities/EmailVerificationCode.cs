using System.ComponentModel.DataAnnotations;

namespace Core.Entities;

public class EmailVerificationCode
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid UserId { get; set; }

    [Required]
    [MaxLength(6)]
    public string Code { get; set; } = null!;

    [Required]
    public DateTime ExpiresAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? VerifiedAt { get; set; }

    public bool IsUsed => VerifiedAt != null;
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsValid => !IsUsed && !IsExpired;

    // Navigation
    public virtual User User { get; set; } = null!;
}