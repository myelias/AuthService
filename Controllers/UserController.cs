using Microsoft.AspNetCore.Mvc;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers
{
    /// <summary>
    /// Controller for user-related operations
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;

        /// <summary>
        /// Constructor - Initializes the user service
        /// </summary>
        /// <param name="userService">User service for handling user operations</param>
        public UserController(IUserService userService, IJwtTokenService jwtTokenService)
        {
            _userService = userService;
            _jwtTokenService = jwtTokenService;
        }

        // Additional methods for user operations can be added here
        [HttpPost("create-user")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequestDto user)
        {
            if (user == null)
            {
                return BadRequest("User data is required.");
            }
            
            try
            {
                var createdUser = await _userService.CreateUserAsync(user);
                return Ok(createdUser);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        
        [HttpGet("{userId}")]
        public async Task<IActionResult> GetUserById(Guid userId)
        {
            if (userId == Guid.Empty)
            {
                return BadRequest("Invalid user ID.");
            }

            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return NotFound($"User with ID {userId} not found.");
                }
                return Ok(user);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet("test-jwt")]
        public IActionResult GetTestJwt()
        {
            // Create a dummy user for token generation
            var dummyUser = new UserInfo
            {
                Id = Guid.NewGuid(),
                Username = "testuser",
                Name = "Test User",
                Email = "test@example.com"
            };

            // Generate JWT token
            var token = _jwtTokenService.GenerateToken(dummyUser);

            return Ok(new { Token = token });
        }
    }
}   