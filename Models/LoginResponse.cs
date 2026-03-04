namespace AuthService.Models;

public class LoginResponse
{
    public string Token {get; set;} = string.Empty;

    public UserInfo User { get; set; } = new UserInfo();

    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddHours(24);

    public string TokenType { get; set; } = "Bearer";
}
