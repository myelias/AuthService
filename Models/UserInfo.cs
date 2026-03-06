using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class UserInfo
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid(); // Use GUID for better uniqueness

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required]
        [MaxLength(50)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [MaxLength(256)]
        public string PasswordHash { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

        public DateTime LastLogin { get; set; } = DateTime.UtcNow;

        public string jwt {get; set;} = string.Empty;
    }
}