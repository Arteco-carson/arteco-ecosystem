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
    public class ArtistsController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;

        public ArtistsController(ArtContext context, IAuditService auditService)
        {
            _context = context;
            _auditService = auditService;
        }

        // GET: api/Artists
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Artist>>> GetArtists()
        {
            return await _context.Artists.OrderBy(a => a.LastName).ThenBy(a => a.FirstName).ToListAsync();
        }

        // POST: api/Artists
        [HttpPost]
        public async Task<ActionResult<Artist>> PostArtist(ArtistCreateDto artistDto)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var artist = new Artist
            {
                FirstName = artistDto.FirstName ?? string.Empty,
                LastName = artistDto.LastName,
                Pseudonym = artistDto.Pseudonym,
                Nationality = artistDto.Nationality,
                BirthYear = artistDto.BirthYear,
                DeathYear = artistDto.DeathYear,
                Biography = artistDto.Biography,
                CreatedAt = System.DateTime.UtcNow
            };

            _context.Artists.Add(artist);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("Artists", artist.ArtistId, "INSERT", profileId, null, artist);

            return CreatedAtAction(nameof(GetArtist), new { id = artist.ArtistId }, artist);
        }

        // GET: api/Artists/5
        [HttpGet("{id}")]
        public async Task<ActionResult<object>> GetArtist(int id)
        {
            var artist = await _context.Artists
                .Where(a => a.ArtistId == id)
                .Select(a => new {
                    a.ArtistId,
                    a.FirstName,
                    a.LastName,
                    a.Pseudonym,
                    a.Nationality,
                    a.BirthYear,
                    a.DeathYear,
                    a.Biography,
                    a.ProfileImageUrl,
                    Artworks = a.Artworks.Select(w => new {
                        w.ArtworkId,
                        w.Title,
                        w.AcquisitionCost
                    }).ToList()
                })
                .FirstOrDefaultAsync();

            if (artist == null)
            {
                return NotFound();
            }

            return artist;
        }

        // PUT: api/Artists/5
        [HttpPut("{id}")]
        public async Task<IActionResult> PutArtist(int id, [FromBody] ArtistUpdateDto artistDto)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            if (id != artistDto.ArtistId) return BadRequest("ID mismatch");

            var artist = await _context.Artists.FindAsync(id);
            if (artist == null) return NotFound();

            // Snapshot old state
            var oldState = new { artist.FirstName, artist.LastName, artist.Pseudonym, artist.Nationality, artist.BirthYear, artist.DeathYear, artist.Biography, artist.ProfileImageUrl };

            artist.FirstName = artistDto.FirstName ?? string.Empty;
            artist.LastName = artistDto.LastName ?? string.Empty;
            artist.Pseudonym = artistDto.Pseudonym;
            artist.Nationality = artistDto.Nationality;
            artist.BirthYear = artistDto.BirthYear;
            artist.DeathYear = artistDto.DeathYear;
            artist.Biography = artistDto.Biography;
            artist.ProfileImageUrl = artistDto.ProfileImageUrl;

            await _context.SaveChangesAsync();

            await _auditService.LogAsync("Artists", id, "UPDATE", profileId, oldState, artistDto);

            return NoContent();
        }

        // DELETE: api/Artists/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteArtist(int id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var artist = await _context.Artists.FindAsync(id);
            if (artist == null)
            {
                return NotFound();
            }

            if (await _context.Artworks.AnyAsync(a => a.ArtistId == id))
            {
                return BadRequest(new { message = "Cannot delete artist. They still have artworks in the inventory." });
            }

            // Snapshot for audit
            var oldState = new { artist.FirstName, artist.LastName, artist.Nationality };

            _context.Artists.Remove(artist);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("Artists", id, "DELETE", profileId, oldState, null);

            return NoContent();
        }
    }

    public class ArtistCreateDto
    {
        public string? FirstName { get; set; }
        public required string LastName { get; set; }
        public string? Pseudonym { get; set; }
        public string? Nationality { get; set; }
        public int? BirthYear { get; set; }
        public int? DeathYear { get; set; }
        public string? Biography { get; set; }
        public string? ProfileImageUrl { get; set; }
    }

    public class ArtistUpdateDto
    {
        public int ArtistId { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Pseudonym { get; set; }
        public string? Nationality { get; set; }
        public int? BirthYear { get; set; }
        public int? DeathYear { get; set; }
        public string? Biography { get; set; }
        public string? ProfileImageUrl { get; set; }
    }
}
