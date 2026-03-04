using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers
{
    /// <summary>
    /// Handles authentication operations including Google OAuth login and JWT token management
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class GoogleController : ControllerBase
    {
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IGoogleAuthService _authService;
        private readonly ILogger<GoogleController> _logger;

        /// <summary>
        /// Constructor - Injects required services for authentication operations
        /// </summary>
        public GoogleController(
            IJwtTokenService jwtTokenService, 
            IGoogleAuthService authService,
            ILogger<GoogleController> logger)
        {
            _jwtTokenService = jwtTokenService;
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Initiates the Google OAuth login flow
        /// This endpoint redirects the user to Google's OAuth consent screen
        /// In order to properly test this endpoint, you must copy the url and paste into another tab.
        /// Then the user will be redirected to the Google login page.
        /// </summary>
        /// <param name="returnUrl">URL to redirect to after successful authentication</param>
        /// <returns>Challenge result that redirects to Google OAuth</returns>
        [HttpGet("login")]
        public IActionResult Login(string returnUrl = "/")
        {
            _logger.LogInformation("Initiating Google OAuth login flow");
            
            // Create the callback URL that Google will redirect to after authentication
            var redirectUrl = Url.Action(nameof(signInGoogle), "Google", new { returnUrl });
            
            // Set up authentication properties with the redirect URL
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            
            // Challenge the user with Google OAuth - this redirects to Google's login page
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// Handles the callback from Google OAuth after user authentication
        /// This is where Google redirects the user after they've authenticated
        /// </summary>
        /// <param name="returnUrl">Original return URL from the login request</param>
        /// <returns>JWT token and user information if successful</returns>
        [HttpGet("signin-google")]
        public async Task<IActionResult> signInGoogle(string returnUrl = "/")
        {
            _logger.LogInformation("Processing Google OAuth callback");

            try
            {
                // Authenticate the user using the Google authentication scheme
                // This extracts the user information from Google's response
                var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

                // Check if authentication was successful
                if (!authenticateResult.Succeeded)
                {
                    _logger.LogWarning("Google OAuth authentication failed");
                    return BadRequest(new { error = "Authentication failed" });
                }

                // Extract user information from the authentication result
                var userInfo = _authService.ExtractUserInfoFromClaims(authenticateResult.Principal?.Claims);

                // Validate that we received essential user information
                if (string.IsNullOrEmpty(userInfo.Email))
                {
                    _logger.LogWarning("Email claim not found in Google OAuth response");
                    return BadRequest(new { error = "Email claim not found" });
                }

                _logger.LogInformation("Successfully authenticated user: {Email}", userInfo.Email);

                // Generate a JWT token for the authenticated user
                var token = _jwtTokenService.GenerateToken(userInfo);

                // var redirectWithToken = $"{returnUrl}?token={Uri.EscapeDataString(token)}";
                //var redirectWithToken = $"{returnUrl}/auth/callback";
                var frontendCallbackUrl = "http://localhost:3000/auth/callback";
                Response.Cookies.Append("auth_token", token, new CookieOptions
                {
                    HttpOnly = true, // front-end JS needs to read it
                    Secure = false, // for localhost
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddHours(1),
                    Path = "/"
                });

                return Redirect(frontendCallbackUrl);
                                // Return the token and user information to the client
                // return Ok(new LoginResponse
                // {
                //     Token = token,
                //     User = userInfo
                // });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Google OAuth callback processing");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        /// <summary>
        /// Returns information about the currently authenticated user
        /// Requires a valid JWT token in the Authorization header
        /// </summary>
        /// <returns>Current user information extracted from JWT token</returns>
        [HttpGet("user")]
        [Authorize] // This attribute ensures the user has a valid JWT token
        public IActionResult GetCurrentUser()
        {
            _logger.LogInformation("Retrieving current user information");
            
            // Extract user information from the JWT token claims
            var userInfo = _authService.ExtractUserInfoFromClaims(User.Claims);

            return Ok(userInfo);
        }

        /// <summary>
        /// Handles user logout
        /// With JWT tokens, logout is typically handled client-side by removing the token
        /// </summary>
        /// <returns>Success message</returns>
        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            _logger.LogInformation("User logout requested");

            // Note: With stateless JWT tokens, actual logout is handled client-side
            // The client should remove the token from storage
            // For additional security, you could implement a token blacklist here

            return Ok(new { message = "Logged out successfully" });
        }

        /// <summary>
        /// Use it only as an explicit, inexpensive health-check or when you 
        /// need a single purpose “is session valid?” endpoint (optional).
        /// </summary>
        /// <returns>Token validation status</returns>
        [Authorize]
        [HttpGet("validate-token")]
        public IActionResult ValidateToken()
        {
            _logger.LogInformation("Token validation requested");

            // If we reach here, the token is valid (due to [Authorize] attribute)
            var userInfo = _authService.ExtractUserInfoFromClaims(User.Claims);

            return Ok(new
            {
                valid = true,
                user = userInfo,
                expiresAt = User.FindFirst("exp")?.Value
            });
        }
        
        [HttpGet("check-cookie")]
        public IActionResult CheckCookie()
        {
            // 1️⃣ Get the token from the cookie
            if (!Request.Cookies.TryGetValue("auth_token", out var token))
            {
                return Unauthorized(new { valid = false, message = "Missing auth token" });
            }

            // 2️⃣ Validate it using your existing JwtTokenService
            var principal = _jwtTokenService.ValidateToken(token);

            // 3️⃣ Handle validation result
                if (principal == null)
                {
                    return Unauthorized(new { valid = false, message = "Invalid or expired token" });
                }

                // 4️⃣ Optionally extract user info (reuse your existing GoogleAuthService logic)
                var userInfo = _authService.ExtractUserInfoFromClaims(principal.Claims);

                return Ok(new
                {
                    valid = true,
                    user = userInfo
                });
            }
    }
}