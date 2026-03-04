using AuthService.Models;
using AuthService.Services;
using AuthService.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;


public class UserService : IUserService
{
    private readonly UserDbContext _context;
    private readonly PasswordHasher<UserInfo> _passwordHasher = new();

    public UserService(UserDbContext context)
    {
        _context = context;
    }

    public async Task<UserInfo?> ValidateCredentialsAsync(string username, string password)
    {
        // Look up the user in the database
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username || u.Email == username);

        if (user == null)
            return null;

        // Verify the password
        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Success)
        {
            return user;
        }

        return null;
    }

    public async Task<CreateUserResponseDto> CreateUserAsync(CreateUserRequestDto user)
    {   

        var userResponse = new CreateUserResponseDto();
        try 
        { 
            // ✅ CHECK: Does user already exist by email?
            var existingUser = await GetExistingUserByEmailAsync(user.Email);
            
            if (existingUser != null)
            {
                // User exists - return them instead of throwing error
                userResponse.userInfo = existingUser;
                userResponse.isEmailRegistered = true;
                return userResponse;
            }

            // ✅ OPTIONAL: Check if username is taken (if usernames must be unique)
            // if (await _context.Users.AnyAsync(u => u.Username == user.Username))
            // {
            //     throw new Exception("Username already exists.");
            // }

            // ✅ CREATE: New user object
            var newUser = new UserInfo
            {
                Id = Guid.NewGuid(),
                Username = user.Username,
                Name = user.Name,
                Email = user.Email,
                PasswordHash = _passwordHasher.HashPassword(null, user.Password),
                CreatedAt = DateTime.UtcNow,
                LastUpdated = DateTime.UtcNow,
            };

            // ✅ SAVE: Add and persist to database
            _context.Users.Add(newUser);
            userResponse.userInfo = newUser;
            userResponse.isEmailRegistered = false;

            await _context.SaveChangesAsync();

            return userResponse;
        }
        catch (Exception ex)
        {
            // Log the error (add proper logging here)
            throw new Exception($"Error creating user: {ex.Message}", ex);
        }
    }
    public async Task<ResponseUserDto?> GetUserByIdAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return null;

        // Map UserInfo to ResponseUserDto
        var response = new ResponseUserDto
        {
            Id = user.Id,
            Username = user.Username,
            Name = user.Name,
            Email = user.Email,
            // Add other properties as needed, but exclude sensitive ones like PasswordHash
        };

        return response;
    }

    private async Task<UserInfo> GetExistingUserByEmailAsync(string email)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
    }
}

