using System.Security.Claims;
using AuthService.Models;

namespace AuthService.Services
{
    /// <summary>
    /// Interface for authentication-related operations
    /// </summary>
    public interface IGoogleAuthService
    {
        /// <summary>
        /// Extracts user information from authentication claims
        /// </summary>
        /// <param name="claims">Collection of claims from authentication result</param>
        /// <returns>UserInfo object containing extracted user data</returns>
        UserInfo ExtractUserInfoFromClaims(IEnumerable<Claim>? claims);

        /// <summary>
        /// Validates if user information is complete and valid
        /// </summary>
        /// <param name="userInfo">User information to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        bool IsValidUserInfo(UserInfo userInfo);
    }
    
}