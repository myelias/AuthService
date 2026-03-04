namespace AuthService.Models;

public class LoginRequest
{
    public string? ReturnUrl { get; set; }

    public string? State { get; set; }
}