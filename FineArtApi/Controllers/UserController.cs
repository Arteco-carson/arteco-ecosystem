using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Security.Claims;
using System.Threading.Tasks;
using FineArtApi.Services;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // This triggers the 401 if the token isn't perfect
    public class UserController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;

        public UserController(ArtContext context, IAuditService auditService)
        {
            _context = context;
            _auditService = auditService;
        }

        [HttpGet("profile")]
        public async Task<ActionResult<object>> GetProfile()
        {
            // The ClaimTypes.NameIdentifier must match what was set in your Login method
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id");
            
            if (userIdClaim == null) 
                return Unauthorized(new { message = "Security Identity claim missing from token." });

            if (!int.TryParse(userIdClaim.Value, out int profileId))
            {
                return BadRequest(new { message = "Invalid Profile Identity format." });
            }

            var user = await _context.UserProfiles
                .Include(u => u.Role)
                .Include(u => u.UserType)
                .FirstOrDefaultAsync(u => u.ProfileId == profileId);

            if (user == null) return NotFound();

            // Explicitly mapping to camelCase for the React Frontend
            return Ok(new
            {
                firstName = user.FirstName ?? "",
                lastName = user.LastName ?? "",
                username = user.Username,
                userRole = user.Role?.RoleName ?? "Guest",
                userType = user.UserType?.UserTypeName,
                roleId = user.RoleId,
                emailAddress = user.EmailAddress,
                telephoneNumber = user.TelephoneNumber,
                currencyCode = user.CurrencyCode
            });
        }

        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UserProfileUpdateDto updateDto)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var user = await _context.UserProfiles.FindAsync(profileId);
            if (user == null) return NotFound();

            // Snapshot old state
            var oldState = new { user.FirstName, user.LastName, user.EmailAddress, user.TelephoneNumber, user.RoleId, user.CurrencyCode };

            user.FirstName = updateDto.FirstName;
            user.LastName = updateDto.LastName;
            user.EmailAddress = updateDto.EmailAddress;
            user.TelephoneNumber = updateDto.TelephoneNumber;

            if (updateDto.RoleId.HasValue)
            {
                user.RoleId = updateDto.RoleId.Value;
            }

            if (!string.IsNullOrEmpty(updateDto.CurrencyCode))
            {
                user.CurrencyCode = updateDto.CurrencyCode;
            }

            await _context.SaveChangesAsync();

            await _auditService.LogAsync("UserProfiles", profileId, "UPDATE", profileId, oldState, updateDto);

            return Ok(new { message = "Profile updated successfully." });
        }

        [HttpGet("currencies")]
        public async Task<ActionResult<IEnumerable<object>>> GetCurrencies()
        {
            return await _context.Set<Currency>()
                .Select(c => new { c.CurrencyCode, c.CurrencyName, c.Country })
                .ToListAsync();
        }

        [HttpGet("customers")]
        public async Task<ActionResult<IEnumerable<object>>> GetCustomers()
        {
            // Only Employees or Admins can list customers
            var userTypeClaim = User.FindFirst("usertype");
            var roleClaim = User.FindFirst(ClaimTypes.Role);
            if ((userTypeClaim == null || userTypeClaim.Value != "Employee") && (roleClaim == null || roleClaim.Value != "Administrator"))
            {
                return Forbid();
            }

            return await _context.UserProfiles
                .Include(u => u.UserType)
                .Where(u => u.UserType != null && u.UserType.UserTypeName == "Customer")
                .Select(u => new
                {
                    id = u.ProfileId,
                    name = !string.IsNullOrEmpty(u.FirstName) && !string.IsNullOrEmpty(u.LastName) ? $"{u.FirstName} {u.LastName}" : u.Username,
                    email = u.EmailAddress
                })
                .ToListAsync();
        }
    }

    public class UserProfileUpdateDto
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string EmailAddress { get; set; } = null!;
        public string? TelephoneNumber { get; set; }
        public int? RoleId { get; set; }
        public string? CurrencyCode { get; set; }
    }
}