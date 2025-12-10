using System.ComponentModel.DataAnnotations;

namespace Core.Entities;

public class Role
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(50)]
    public string Name { get; set; } = null!;

    [MaxLength(200)]
    public string? Description { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    // Navigation
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}