using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Models;

namespace AuthService.Services
{
    /// <summary>
    /// Interface for JWT token operations
    /// </summary>
    public interface IJwtTokenService
    {
        /// <summary>
        /// Generates a JWT token for the given user information
        /// </summary>
        /// <param name="userInfo">User information to include in the token</param>
        /// <returns>JWT token as a string</returns>
        string GenerateToken(UserInfo userInfo);

        /// <summary>
        /// Validates a JWT token
        /// </summary>
        /// <param name="token">Token to validate</param>
        /// <returns>ClaimsPrincipal if valid, null if invalid</returns>
        ClaimsPrincipal? ValidateToken(string token);
    }

    /// <summary>
    /// Service responsible for creating and validating JWT tokens
    /// This service encapsulates all JWT-related operations
    /// </summary>
    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtTokenService> _logger;

        /// <summary>
        /// JWT configuration settings extracted from appsettings.json
        /// </summary>
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _expiryInHours;

        /// <summary>
        /// Constructor - Initializes JWT settings from configuration
        /// </summary>
        /// <param name="configuration">Application configuration</param>
        /// <param name="logger">Logger for this service</param>
        public JwtTokenService(IConfiguration configuration, ILogger<JwtTokenService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            // Extract JWT settings from configuration with validation
            var jwtSettings = _configuration.GetSection("JwtSettings");
            _secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
            _issuer = jwtSettings["Issuer"] ?? "YourApp";
            _audience = jwtSettings["Audience"] ?? "YourAppUsers";
            _expiryInHours = int.Parse(jwtSettings["ExpiryInHours"] ?? "72");

            // Validate secret key length for security
            if (_secretKey.Length < 32)
            {
                throw new InvalidOperationException("JWT SecretKey must be at least 32 characters long for security");
            }
        }

        /// <summary>
        /// Generates a JWT token containing user information and authentication claims
        /// </summary>
        /// <param name="userInfo">User information to encode in the token</param>
        /// <returns>Signed JWT token as a string</returns>
        public string GenerateToken(UserInfo userInfo)
        {
            _logger.LogInformation("Generating JWT token for user: {Email}", userInfo.Email);

            try
            {
                // Create the signing key from the secret
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                // Build the claims that will be included in the token
                var claims = new List<Claim>
                {
                    // Standard JWT claims
                    new Claim(JwtRegisteredClaimNames.Sub, userInfo.Id != Guid.Empty ? userInfo.Id.ToString() : userInfo.Email), // Subject (user identifier)
                    new(JwtRegisteredClaimNames.Email, userInfo.Email),              // Email address
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),    // JWT ID (unique token identifier)
                    new(JwtRegisteredClaimNames.Iat,                                 // Issued at time
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), 
                        ClaimValueTypes.Integer64),
                    
                    // Custom claims for ASP.NET Core identity
                    new(ClaimTypes.Email, userInfo.Email),
                    new(ClaimTypes.NameIdentifier, userInfo.Id != Guid.Empty ? userInfo.Id.ToString() : userInfo.Email)
                };

                // Add optional name claim if provided
                if (!string.IsNullOrEmpty(userInfo.Name))
                {
                    claims.Add(new Claim(ClaimTypes.Name, userInfo.Name));
                    claims.Add(new Claim(JwtRegisteredClaimNames.Name, userInfo.Name));
                }

                // Create the JWT token with all settings
                var token = new JwtSecurityToken(
                    issuer: _issuer,                                    // Who issued the token
                    audience: _audience,                                // Who the token is intended for
                    claims: claims,                                     // User information and metadata
                    expires: DateTime.UtcNow.AddHours(_expiryInHours), // When the token expires
                    signingCredentials: credentials                     // How to verify the token signature
                );

                // Serialize the token to a string
                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                
                _logger.LogInformation("JWT token generated successfully for user: {Email}", userInfo.Email);
                return tokenString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating JWT token for user: {Email}", userInfo.Email);
                throw;
            }
        }

        /// <summary>
        /// Validates a JWT token and returns the claims if valid
        /// This is useful for manual token validation outside of the middleware
        /// </summary>
        /// <param name="token">The JWT token to validate</param>
        /// <returns>ClaimsPrincipal containing user information if valid, null if invalid</returns>
        public ClaimsPrincipal? ValidateToken(string token)
        {
            _logger.LogInformation("Validating JWT token");

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                // Set up validation parameters - these must match the token generation settings
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,              // Check if token is expired
                    ValidateIssuerSigningKey = true,      // Verify the signature
                    ValidIssuer = _issuer,
                    ValidAudience = _audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero             // No tolerance for time differences
                };

                // Validate the token and extract claims
                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                
                _logger.LogInformation("JWT token validated successfully");
                return principal;
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "JWT token validation failed: {Message}", ex.Message);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during JWT token validation");
                return null;
            }
        }
    }
}