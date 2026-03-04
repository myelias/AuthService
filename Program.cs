using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.Google;
using System.Text;
using AuthService.Services;
using Microsoft.EntityFrameworkCore;
using AuthService.Data;
using Microsoft.OpenApi.Models; // Add this line if AppDbContext is in the Data folder/namespace


var builder = WebApplication.CreateBuilder(args);
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
/*
 * AUTHENTICATION SETUP
 * This section configures multiple authentication schemes:
 * 1. Cookie authentication for the OAuth flow
 * 2. Google OAuth for external authentication
 * 3. JWT Bearer for API authentication
 */

// Configure Google OAuth authentication
// We use a dual authentication scheme: cookies for OAuth flow, JWT for API access
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // ...existing code...
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement{
        {
            new OpenApiSecurityScheme{
                Reference = new OpenApiReference{
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            }, new List<string>()
        }
    });
});
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();
builder.Services.AddScoped<IGoogleAuthService, GoogleAuthService>();
builder.Services.AddScoped<IUserService, UserService>();
// builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddCors(options =>
{
    // Existing policy for Swagger UI
    options.AddPolicy("AllowSwaggerUI", policy =>
    {
        policy.WithOrigins(
                "http://localhost:3000",    // React Front End
                "http://localhost:5217",    // HTTP Swagger UI origin
                "https://localhost:7084"    // If you run HTTPS profile too
            )
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });

    // Optional: explicit frontend policy
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:3000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // important for sending cookies
    });
});
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme; // For OAuth temporary ticket
})
// Add cookie authentication for OAuth flow state management
// Cookies are needed during the OAuth redirect flow to maintain state
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/api/auth/login";        // Where to redirect for login
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Short-lived for security
    options.SlidingExpiration = false;           // Don't extend expiration on activity
    options.Cookie.SameSite = SameSiteMode.Lax;  // Allow cross-site requests for OAuth
})
// Add Google OAuth provider
.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
{
    // Load Google OAuth credentials from configuration
    options.ClientId = builder.Configuration["GoogleAuth:ClientId"] 
        ?? throw new InvalidOperationException("Google ClientId not configured");
    options.ClientSecret = builder.Configuration["GoogleAuth:ClientSecret"]
        ?? throw new InvalidOperationException("Google ClientSecret not configured");
    
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    // Request additional scopes beyond basic authentication
    options.Scope.Add("email");     // Access to user's email address
    options.Scope.Add("profile");   // Access to user's basic profile info
    
    // Configure how user information is saved to claims
    options.SaveTokens = true;      // Save OAuth tokens for potential future use
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSettings["Audience"],
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader))
        {
            if (context.Request.Cookies.TryGetValue("auth_token", out var cookieToken))
            {
                context.Token = cookieToken;
            }
        }
        return Task.CompletedTask;
    }
    };
});
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
/*
 * JWT BEARER AUTHENTICATION SETUP
 * This is used for API authentication after the initial OAuth login
 */

// Extract JWT configuration settings

// Validate JWT secret key security
if (secretKey.Length < 32)
{
    throw new InvalidOperationException("JWT SecretKey must be at least 32 characters for security");
}

/*
 * AUTHORIZATION SETUP
 * Configure how authorization decisions are made
 */
builder.Services.AddAuthorization(options =>
{
    // Default policy requires JWT authentication for all protected endpoints
    options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .Build();
    
    // You can add additional policies here for role-based or claim-based authorization
    // Example: Admin-only policy
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("role", "admin")
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme));
});

/*
 * APPLICATION PIPELINE CONFIGURATION
 * The order of middleware registration is critical - each request flows through
 * these components in the order they're registered
 */

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    // Enable Swagger UI for API documentation in development
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API V1");
        c.OAuthClientId(builder.Configuration["GoogleAuth:ClientId"]);
        c.OAuthAppName("Auth API");
        c.OAuthUsePkce(); // Use PKCE for security
        c.OAuthUseBasicAuthenticationWithAccessCodeGrant();
    });
    
    // Show detailed error pages in development
    app.UseDeveloperExceptionPage();
}
else
{
    // Use generic error handling in production
    app.UseExceptionHandler("/Error");
    // Enable HSTS (HTTP Strict Transport Security)
    app.UseHsts();
}

// Force HTTPS redirection
// Only redirect to HTTPS in non-development environments
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// Enable CORS if needed (configure based on your frontend requirements)
//app.UseCors("AllowSwaggerUI");
app.UseCors("AllowFrontend");


/*
 * AUTHENTICATION & AUTHORIZATION MIDDLEWARE
 * These must be in the correct order:
 * 1. Authentication (who is the user?)
 * 2. Authorization (what can they do?)
 */

// Authentication middleware - processes tokens and sets User identity
app.UseAuthentication();

// Authorization middleware - enforces access policies
app.UseAuthorization();

// Map controller endpoints
app.MapControllers();

// Optional: Add a health check endpoint
app.MapGet("/health", () => Results.Ok(new { 
    status = "healthy", 
    timestamp = DateTime.UtcNow,
    version = "1.0.0"
})).AllowAnonymous();

// Log startup information
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("Application started successfully");
logger.LogInformation("Google OAuth ClientId configured: {HasClientId}", 
    !string.IsNullOrEmpty(builder.Configuration["GoogleAuth:ClientId"]));

app.Run();