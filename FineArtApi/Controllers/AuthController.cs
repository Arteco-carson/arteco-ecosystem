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
            if (await _context.UserProfiles.AnyAsync(u => u.Username == registerDto.Username))
                return BadRequest(new { message = "Username already exists" });

            CreatePasswordHash(registerDto.Password, out string passwordHash, out string passwordSalt);

            // Determine UserType (Customer, Employee) based on input
            var userType = await _context.UserTypes.FirstOrDefaultAsync(ut => ut.UserTypeName == registerDto.UserRole);
            
            // Determine System Role. Default to Guest unless Admin is explicitly requested.
            string roleName = (registerDto.UserRole == "Admin" || registerDto.UserRole == "Administrator") ? "Administrator" : "Guest";
            var role = await _context.Set<UserRole>().FirstOrDefaultAsync(r => r.RoleName == roleName) 
                       ?? await _context.Set<UserRole>().FirstAsync(r => r.RoleName == "Guest");

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
                RoleId = role.RoleId,
                UserTypeId = userType?.UserTypeId,
                IsActive = true,
                MarketingConsent = registerDto.MarketingConsent
            };

            _context.UserProfiles.Add(user);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("UserProfiles", user.ProfileId, "INSERT", user.ProfileId, null, new { user.Username, user.EmailAddress, user.RoleId });

            return Ok(new { message = "Registration successful" });
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
        [JsonPropertyName("userRole")]
        public string UserRole { get; set; } = "Guest";
        [JsonPropertyName("marketingConsent")]
        public bool MarketingConsent { get; set; }
    }
}