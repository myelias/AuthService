namespace AuthService.Models
{
    public class ResponseUserDto
    {
        public Guid Id { get; set; }  

        public string Email { get; set; } = string.Empty;

        public string Name { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        // public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }
}