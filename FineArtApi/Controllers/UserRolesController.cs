using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserRolesController : ControllerBase
    {
        private readonly ArtContext _context;

        public UserRolesController(ArtContext context)
        {
            _context = context;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<object>>> GetUserRoles()
        {
            try
            {
                // Use projection to avoid serialization loops and ensure only necessary data is sent
                return await _context.Set<UserRole>()
                    .Select(r => new { r.RoleId, r.RoleName })
                    .ToListAsync();
            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine($"[Error] GetUserRoles: {ex.Message}");
                return StatusCode(500, new { message = $"Error fetching roles: {ex.Message}", details = ex.ToString() });
            }
        }
    }
}