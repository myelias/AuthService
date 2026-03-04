namespace AuthService.Models;

public class TokenValidationResponse
    {
        public bool IsValid { get; set; }

        public UserInfo? User { get; set; }

        public DateTime? ExpiresAt { get; set; }

        public string? Error { get; set; }
    }