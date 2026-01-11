using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using FineArtApi.Services;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class LocationsController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;

        public LocationsController(ArtContext context, IAuditService auditService)
        {
            _context = context;
            _auditService = auditService;
        }

        // GET: api/Locations
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Location>>> GetLocations()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            return await _context.Set<Location>()
                .Where(l => l.UserLocations.Any(ul => ul.ProfileId == profileId))
                .OrderBy(l => l.LocationName)
                .ToListAsync();
        }

        // GET: api/Locations/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Location>> GetLocation(int id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var location = await _context.Set<Location>()
                .Include(l => l.UserLocations)
                .FirstOrDefaultAsync(l => l.LocationId == id && l.UserLocations.Any(ul => ul.ProfileId == profileId));

            if (location == null)
            {
                return NotFound();
            }

            return location;
        }

        // POST: api/Locations
        [HttpPost]
        public async Task<ActionResult<Location>> PostLocation(Location location)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            // If the new location is set as default, unset any existing default for this user
            if (location.IsDefault)
            {
                var existingDefaults = await _context.Set<UserLocation>()
                    .Where(ul => ul.ProfileId == profileId && ul.IsDefault == true)
                    .ToListAsync();

                foreach (var def in existingDefaults)
                {
                    def.IsDefault = false;
                }
            }

            _context.Set<Location>().Add(location);
            await _context.SaveChangesAsync();

            // Link the new location to the creating user
            var userLocation = new UserLocation
            {
                ProfileId = profileId,
                LocationId = location.LocationId,
                AssignedDate = DateTime.UtcNow,
                IsDefault = location.IsDefault
            };
            _context.Add(userLocation);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("Locations", location.LocationId, "INSERT", profileId, null, location);

            return CreatedAtAction(nameof(GetLocation), new { id = location.LocationId }, location);
        }

        // PUT: api/Locations/5
        [HttpPut("{id}")]
        public async Task<IActionResult> PutLocation(int id, Location location)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            if (id != location.LocationId)
            {
                return BadRequest();
            }

            // Fetch existing location to verify access and capture old state
            var existingLocation = await _context.Set<Location>()
                .Include(l => l.UserLocations)
                .FirstOrDefaultAsync(l => l.LocationId == id && l.UserLocations.Any(ul => ul.ProfileId == profileId));
            
            if (existingLocation == null)
            {
                return NotFound();
            }

            // Snapshot old state
            var oldState = new { existingLocation.LocationName, existingLocation.AddressLine1, existingLocation.City, existingLocation.Postcode, existingLocation.Country, existingLocation.IsDefault };

            // Update properties
            existingLocation.LocationName = location.LocationName;
            existingLocation.AddressLine1 = location.AddressLine1;
            existingLocation.City = location.City;
            existingLocation.Postcode = location.Postcode;
            existingLocation.Country = location.Country;
            existingLocation.IsDefault = location.IsDefault;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!LocationExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            await _auditService.LogAsync("Locations", id, "UPDATE", profileId, oldState, location);

            return NoContent();
        }

        // DELETE: api/Locations/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteLocation(int id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            // Check if any artworks are currently assigned to this location
            var hasArtworks = await _context.Artworks.AnyAsync(a => a.CurrentLocationId == id);
            if (hasArtworks)
            {
                return BadRequest(new { message = "Cannot delete location. There are artworks currently assigned to this location." });
            }

            var location = await _context.Set<Location>()
                .Include(l => l.UserLocations)
                .FirstOrDefaultAsync(l => l.LocationId == id && l.UserLocations.Any(ul => ul.ProfileId == profileId));

            if (location == null)
            {
                return NotFound();
            }

            // Snapshot for audit
            var oldState = new { location.LocationName, location.AddressLine1, location.City, location.Country };

            // Explicitly remove UserLocations to ensure referential integrity
            if (location.UserLocations != null && location.UserLocations.Any())
            {
                _context.Set<UserLocation>().RemoveRange(location.UserLocations);
            }

            _context.Set<Location>().Remove(location);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("Locations", id, "DELETE", profileId, oldState, null);

            return NoContent();
        }

        private bool LocationExists(int id)
        {
            return _context.Set<Location>().Any(e => e.LocationId == id);
        }
    }
}