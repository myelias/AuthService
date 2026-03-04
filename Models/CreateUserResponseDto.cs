using System.Runtime.CompilerServices;
using AuthService.Models;

public class CreateUserResponseDto
{
    public UserInfo userInfo { get; set; }

    public bool isEmailRegistered { get; set; } = false;
}