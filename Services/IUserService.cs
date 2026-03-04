using AuthService.Models;
namespace AuthService.Services
{
    /// <summary>
    /// Interface for user-related operations
    /// </summary>
    public interface IUserService
    {
        Task<UserInfo?> ValidateCredentialsAsync(string username, string password);
        /// <summary>
        /// Creates a new user in the system
        /// </summary>
        /// <param name="user">User information to create</param>
        /// <returns>Created UserInfo object</returns>
        Task<CreateUserResponseDto> CreateUserAsync(CreateUserRequestDto user);

        /// <summary>
        /// Retrieves a user by their unique identifier
        /// </summary>
        /// <param name="userId">Unique identifier of the user</param>
        /// <returns>UserInfo object if found, null otherwise</returns>
        Task<ResponseUserDto?> GetUserByIdAsync(Guid userId);
    }
}