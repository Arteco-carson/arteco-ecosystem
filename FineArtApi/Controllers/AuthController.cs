using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text.Json.Serialization;
using FineArtApi.Services;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IConfiguration _configuration;
        private readonly IAuditService _auditService;

        public AuthController(ArtContext context, IConfiguration configuration, IAuditService auditService)
        {
            _context = context;
            _configuration = configuration;
            _auditService = auditService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            try
            {
                if (await _context.UserProfiles.AnyAsync(u => u.Username == registerDto.Username))
                    return BadRequest(new { message = "Username already exists" });

                CreatePasswordHash(registerDto.Password, out string passwordHash, out string passwordSalt);

                // Validate RoleId exists
                if (!await _context.Set<UserRole>().AnyAsync(r => r.RoleId == registerDto.RoleId))
                    return BadRequest(new { message = "Invalid Role ID" });

                // Validate UserTypeId exists
                if (!await _context.UserTypes.AnyAsync(ut => ut.UserTypeId == registerDto.UserTypeId))
                    return BadRequest(new { message = "Invalid User Type ID" });

                var user = new UserProfile
                {
                    Username = registerDto.Username,
                    EmailAddress = registerDto.Email,
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    PasswordHash = passwordHash,
                    Salt = passwordSalt,
                    CreatedAt = DateTime.UtcNow,
                    ExternalUserId = Guid.NewGuid().ToString(),
                    RoleId = registerDto.RoleId,
                    UserTypeId = registerDto.UserTypeId,
                    IsActive = true,
                    MarketingConsent = registerDto.MarketingConsent
                };

                _context.UserProfiles.Add(user);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("UserProfiles", user.ProfileId, "INSERT", user.ProfileId, null, new { user.Username, user.EmailAddress, user.RoleId, user.UserTypeId });

                return Ok(new { message = "Registration successful" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Register Error] {ex}");
                return StatusCode(500, new { message = $"Registration Error: {ex.Message}", details = ex.ToString() });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var user = await _context.UserProfiles
                .Include(u => u.Role)
                .Include(u => u.UserType)
                .SingleOrDefaultAsync(u => u.Username == loginDto.Username);

            if (user == null) return Unauthorized(new { message = "Invalid credentials" });

            if (!VerifyPasswordHash(loginDto.Password, user.PasswordHash, user.Salt))
                return Unauthorized(new { message = "Invalid credentials" });

            var tokenHandler = new JwtSecurityTokenHandler();
            // Use a secure key from config in production
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? "SuperSecretKeyForDevelopmentOnly12345!"); 
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.ProfileId.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim("id", user.ProfileId.ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, user.ProfileId.ToString()),
                    new Claim(ClaimTypes.Role, user.Role?.RoleName ?? "Guest"),
                    new Claim("usertype", user.UserType?.UserTypeName ?? "")
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var oldLoginDate = user.LastLoginDate;
            // Update last login
            user.LastLoginDate = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("UserProfiles", user.ProfileId, "UPDATE", user.ProfileId, new { LastLoginDate = oldLoginDate }, new { user.LastLoginDate });

            return Ok(new { token = tokenString, userType = user.UserType?.UserTypeName });
        }

        // Endpoint for the Defect Reporting mobile app
        [HttpPost("login-dr")]
        public async Task<IActionResult> LoginDr([FromBody] LoginDto loginDto)
        {
            try
            {
                var user = await _context.UserProfiles
                    .Include(u => u.Role)
                    .SingleOrDefaultAsync(u => u.Username == loginDto.Username);

                if (user == null)
                {
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                if (!VerifyPasswordHash(loginDto.Password, user.PasswordHash, user.Salt))
                {
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                var employeeUserType = await _context.UserTypes.SingleOrDefaultAsync(ut => ut.UserTypeName == "Employee");
                if (employeeUserType == null)
                {
                    // This is a data setup problem.
                    return StatusCode(500, new { message = "Server configuration error: 'Employee' user type not found." });
                }

                if (user.UserTypeId != employeeUserType.UserTypeId)
                {
                    return Unauthorized(new { message = "Access denied. Only employees can log in." });
                }

                // Eagerly load the UserType now that we have validated the user
                var userType = await _context.UserTypes.FindAsync(user.UserTypeId);

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? "SuperSecretKeyForDevelopmentOnly12345!");
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.ProfileId.ToString()),
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim("id", user.ProfileId.ToString()),
                        new Claim(JwtRegisteredClaimNames.Sub, user.ProfileId.ToString()),
                        new Claim(ClaimTypes.Role, user.Role?.RoleName ?? "Guest"),
                        new Claim("usertype", userType?.UserTypeName ?? "")
                    }),
                    Expires = DateTime.UtcNow.AddDays(7),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                var oldLoginDate = user.LastLoginDate;
                user.LastLoginDate = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("UserProfiles", user.ProfileId, "UPDATE", user.ProfileId, new { LastLoginDate = oldLoginDate }, new { LastLoginDate = user.LastLoginDate });

                return Ok(new { token = tokenString, userType = userType?.UserTypeName });
            }
            catch (Exception ex)
            {
                // Log the exception details for debugging
                Console.WriteLine($"[LoginDr Error] {ex}");
                return StatusCode(500, new { message = $"An unexpected server error occurred: {ex.Message}", details = ex.ToString() });
            }
        }

        [HttpPost("register-dr")]
        public async Task<IActionResult> RegisterDr([FromBody] RegisterDrDto registerDto)
        {
            try
            {
                if (await _context.UserProfiles.AnyAsync(u => u.Username == registerDto.Username))
                    return BadRequest(new { message = "Username already exists" });

                if (await _context.UserProfiles.AnyAsync(u => u.EmailAddress == registerDto.Email))
                    return BadRequest(new { message = "Email address already in use" });

                var employeeUserType = await _context.UserTypes.SingleOrDefaultAsync(ut => ut.UserTypeName == "Employee");
                if (employeeUserType == null)
                {
                    return StatusCode(500, new { message = "Server configuration error: 'Employee' user type not found." });
                }

                var guestRole = await _context.UserRoles.SingleOrDefaultAsync(ur => ur.RoleName == "Guest");
                if (guestRole == null)
                {
                    return StatusCode(500, new { message = "Server configuration error: 'Guest' role not found." });
                }

                CreatePasswordHash(registerDto.Password, out string passwordHash, out string passwordSalt);

                var user = new UserProfile
                {
                    Username = registerDto.Username,
                    EmailAddress = registerDto.Email,
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    PasswordHash = passwordHash,
                    Salt = passwordSalt,
                    CreatedAt = DateTime.UtcNow,
                    ExternalUserId = Guid.NewGuid().ToString(), // As per existing register endpoint
                    RoleId = guestRole.RoleId,
                    UserTypeId = employeeUserType.UserTypeId,
                    IsActive = true,
                    MarketingConsent = false // Default for this registration type
                };

                _context.UserProfiles.Add(user);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("UserProfiles", user.ProfileId, "INSERT", user.ProfileId, null, new { user.Username, user.EmailAddress, user.RoleId, user.UserTypeId });

                return Ok(new { message = "Registration successful" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RegisterDr Error] {ex}");
                return StatusCode(500, new { message = $"Registration Error: {ex.Message}", details = ex.ToString() });
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetDto)
        {
            if (resetDto.NewPassword != resetDto.ConfirmPassword)
                return BadRequest(new { message = "Passwords do not match." });

            var user = await _context.UserProfiles.SingleOrDefaultAsync(u => u.Username == resetDto.Username);
            if (user == null)
                return BadRequest(new { message = "User not found." });

            if (!VerifyPasswordHash(resetDto.OldPassword, user.PasswordHash, user.Salt))
                return BadRequest(new { message = "Incorrect current password." });

            // Snapshot (excluding sensitive data, just noting the change)
            var oldState = new { PasswordChanged = "OldHash" };

            CreatePasswordHash(resetDto.NewPassword, out string newHash, out string newSalt);
            
            user.PasswordHash = newHash;
            user.Salt = newSalt;
            
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("UserProfiles", user.ProfileId, "UPDATE", user.ProfileId, oldState, new { PasswordChanged = "NewHash" });

            return Ok(new { message = "Password reset successfully." });
        }

        private void CreatePasswordHash(string password, out string passwordHash, out string passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = Convert.ToBase64String(hmac.Key);
                passwordHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
            }
        }

        private bool VerifyPasswordHash(string password, string? storedHash, string? storedSalt)
        {
            if (string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(storedSalt)) return false;
            using (var hmac = new HMACSHA512(Convert.FromBase64String(storedSalt)))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                var storedHashBytes = Convert.FromBase64String(storedHash);
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHashBytes[i]) return false;
                }
            }
            return true;
        }
    }

    public class LoginDto 
    { 
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty; 
        
        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty; 
    }

    public class ResetPasswordDto { 
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;
        [JsonPropertyName("oldPassword")]
        public string OldPassword { get; set; } = string.Empty;
        [JsonPropertyName("newPassword")]
        public string NewPassword { get; set; } = string.Empty;
        [JsonPropertyName("confirmPassword")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class RegisterDto
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;
        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;
        [JsonPropertyName("firstName")]
        public string FirstName { get; set; } = string.Empty;
        [JsonPropertyName("lastName")]
        public string LastName { get; set; } = string.Empty;
        [JsonPropertyName("roleId")]
        public int RoleId { get; set; }
        [JsonPropertyName("userTypeId")]
        public int UserTypeId { get; set; }
                [JsonPropertyName("marketingConsent")]
                public bool MarketingConsent { get; set; }
            }
        
            public class RegisterDrDto
            {
                [JsonPropertyName("username")]
                public string Username { get; set; } = string.Empty;
                [JsonPropertyName("password")]
                public string Password { get; set; } = string.Empty;
                [JsonPropertyName("email")]
                public string Email { get; set; } = string.Empty;
                [JsonPropertyName("firstName")]
                public string FirstName { get; set; } = string.Empty;
                [JsonPropertyName("lastName")]
                public string LastName { get; set; } = string.Empty;
            }
        }
        