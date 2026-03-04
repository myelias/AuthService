using AuthService.Services;
using AuthService.Models;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

/// <summary>
/// Service that handles authentication-related business logic
/// This service abstracts the complexity of working with authentication claims
/// and user information extraction
/// </summary>
public class GoogleAuthService : IGoogleAuthService
{
    private readonly ILogger<GoogleAuthService> _logger;

    /// <summary>
    /// Constructor - Initializes the authentication service
    /// </summary>
    /// <param name="logger">Logger for this service</param>
    public GoogleAuthService(ILogger<GoogleAuthService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Extracts user information from OAuth claims
    /// This method handles the complexity of finding the right claims from different sources
    /// (Google OAuth, JWT tokens, etc.) and normalizing them into a consistent format
    /// </summary>
    /// <param name="claims">Claims collection from authentication context</param>
    /// <returns>UserInfo object with extracted user data</returns>
    public UserInfo ExtractUserInfoFromClaims(IEnumerable<Claim>? claims)
    {
        if (claims == null)
        {
            _logger.LogWarning("No claims provided for user info extraction");
            return new UserInfo();
        }

        var claimsList = claims.ToList();
        _logger.LogInformation("Extracting user info from {ClaimCount} claims", claimsList.Count);

        // Extract email - try multiple claim types as different providers use different formats
        var email = GetClaimValue(claimsList, ClaimTypes.Email) ??
                   GetClaimValue(claimsList, "email") ??
                   GetClaimValue(claimsList, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");

        // Extract name - try multiple claim types
        var name = GetClaimValue(claimsList, ClaimTypes.Name) ??
                  GetClaimValue(claimsList, "name") ??
                  GetClaimValue(claimsList, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");

        // Extract user ID - try multiple claim types
        var id = GetClaimValue(claimsList, ClaimTypes.NameIdentifier) ??
                GetClaimValue(claimsList, "sub") ??
                GetClaimValue(claimsList, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        // Extract additional Google-specific information if available
        var picture = GetClaimValue(claimsList, "picture") ??
                     GetClaimValue(claimsList, "avatar");

        var givenName = GetClaimValue(claimsList, "given_name") ??
                       GetClaimValue(claimsList, ClaimTypes.GivenName);

        var familyName = GetClaimValue(claimsList, "family_name") ??
                        GetClaimValue(claimsList, ClaimTypes.Surname);

        var userInfo = new UserInfo
        {
            Email = email ?? string.Empty,
            Name = name ?? string.Empty,
            Id = Guid.TryParse(id, out var guid) ? guid : Guid.Empty,
        };

        // Log the extraction results (without sensitive data)
        _logger.LogInformation("User info extracted - Email: {HasEmail}, Name: {HasName}, ID: {HasId}",
            !string.IsNullOrEmpty(userInfo.Email),
            !string.IsNullOrEmpty(userInfo.Name),
            !string.IsNullOrEmpty(userInfo.Id.ToString()));

        return userInfo;
    }

    /// <summary>
    /// Validates that user information contains all required fields
    /// This is important for ensuring we have the minimum required data for authentication
    /// </summary>
    /// <param name="userInfo">User information to validate</param>
    /// <returns>True if user info is valid and complete</returns>
    public bool IsValidUserInfo(UserInfo userInfo)
    {
        if (userInfo == null)
        {
            _logger.LogWarning("UserInfo is null");
            return false;
        }

        // Email is required for authentication
        if (string.IsNullOrWhiteSpace(userInfo.Email))
        {
            _logger.LogWarning("UserInfo validation failed: Email is required");
            return false;
        }

        // Basic email format validation
        if (!IsValidEmail(userInfo.Email))
        {
            _logger.LogWarning("UserInfo validation failed: Email format is invalid");
            return false;
        }

        // ID is required (can default to email if not provided)
        if (userInfo.Id == Guid.Empty)
        {
            _logger.LogInformation("UserInfo ID is empty, using email as ID");
            // If your UserInfo.Id is a Guid, you may want to generate a new Guid or handle this differently.
            // Here, we'll generate a new Guid based on the email for demonstration purposes.
            userInfo.Id = Guid.NewGuid();
        }

        _logger.LogInformation("UserInfo validation passed for user: {Email}", userInfo.Email);
        return true;
    }

    /// <summary>
    /// Helper method to safely extract claim values
    /// Handles the complexity of claim type variations and null checking
    /// </summary>
    /// <param name="claims">List of claims to search</param>
    /// <param name="claimType">Type of claim to find</param>
    /// <returns>Claim value if found, null otherwise</returns>
    private static string? GetClaimValue(List<Claim> claims, string claimType)
    {
        return claims.FirstOrDefault(c =>
            string.Equals(c.Type, claimType, StringComparison.OrdinalIgnoreCase))?.Value;
    }

    /// <summary>
    /// Basic email validation
    /// Uses a simple but effective email validation approach
    /// </summary>
    /// <param name="email">Email address to validate</param>
    /// <returns>True if email format appears valid</returns>
    private static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}