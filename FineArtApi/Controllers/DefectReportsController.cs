using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using System;
using FineArtApi.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using System.IO;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class DefectReportsController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DefectReportsController> _logger;

        public DefectReportsController(ArtContext context, IAuditService auditService, IConfiguration configuration, ILogger<DefectReportsController> logger)
        {
            _context = context;
            _auditService = auditService;
            _configuration = configuration;
            _logger = logger;
        }

        // GET: api/DefectReports/artwork/5
        [HttpGet("artwork/{artworkId}")]
        public async Task<ActionResult<IEnumerable<DefectReport>>> GetDefectReports(int artworkId)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            // Verify the user has access to this artwork (ownership check)
            var artwork = await _context.Artworks.FindAsync(artworkId);
            if (artwork == null)
            {
                return NotFound("Artwork not found.");
            }

            var userTypeClaim = User.FindFirst("usertype");
            var roleClaim = User.FindFirst(ClaimTypes.Role);
            bool isEmployee = userTypeClaim?.Value == "Employee" || roleClaim?.Value == "Administrator";

            if (artwork.CreatedByProfileId != profileId && !isEmployee)
            {
                return Forbid();
            }

            return await _context.Set<DefectReport>()
                .Where(d => d.ArtworkId == artworkId)
                .OrderByDescending(d => d.CreatedDate)
                .ToListAsync();
        }

        // POST: api/DefectReports
        [HttpPost]
        public async Task<ActionResult<DefectReport>> PostDefectReport(DefectReport defectReport)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            // Verify ownership of the artwork before adding a report
            var artwork = await _context.Artworks.FindAsync(defectReport.ArtworkId);
            if (artwork == null)
            {
                return NotFound("Artwork not found.");
            }

            var userTypeClaim = User.FindFirst("usertype");
            var roleClaim = User.FindFirst(ClaimTypes.Role);
            bool isEmployee = userTypeClaim?.Value == "Employee" || roleClaim?.Value == "Administrator";

            if (artwork.CreatedByProfileId != profileId && !isEmployee)
            {
                return Forbid();
            }

            // Auto-populate audit fields
            var userProfile = await _context.UserProfiles.FindAsync(profileId);
            defectReport.CreatedBy = userProfile?.Username ?? "Unknown User";
            defectReport.CreatedDate = DateTime.UtcNow;

            // Ensure ReportName is populated if client sent null
            if (string.IsNullOrEmpty(defectReport.ReportName))
            {
                defectReport.ReportName = $"Condition Report - {artwork.Title}";
            }

            _context.Set<DefectReport>().Add(defectReport);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("DefectReports", defectReport.DefectReportId, "INSERT", profileId, null, defectReport);

            // Break circular reference for JSON serialization
            defectReport.Artwork = null;

            return CreatedAtAction(nameof(GetDefectReports), new { artworkId = defectReport.ArtworkId }, defectReport);
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadReport([FromForm] IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    _logger.LogWarning("DefectReportsController: No file received.");
                    return BadRequest("No file uploaded.");
                }

                _logger.LogInformation($"DefectReportsController: Processing {file.FileName}, Size: {file.Length} bytes, Type: {file.ContentType}");
                string connectionString = _configuration["AzureStorage:ConnectionString"] ?? string.Empty;
                string containerName = _configuration["AzureStorage:ReportsContainerName"] ?? "defect-reports";

                if (string.IsNullOrEmpty(connectionString) || connectionString.Contains("YOUR_AZURE_CONNECTION_STRING"))
                {
                    return StatusCode(500, "Azure Storage connection string is not configured.");
                }

                var blobServiceClient = new BlobServiceClient(connectionString);
                var containerClient = blobServiceClient.GetBlobContainerClient(containerName);

                await containerClient.CreateIfNotExistsAsync(PublicAccessType.Blob);

                var fileName = $"report_{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";
                var blobClient = containerClient.GetBlobClient(fileName);

                using (var stream = file.OpenReadStream())
                {
                    var blobHttpHeader = new BlobHttpHeaders { ContentType = file.ContentType };
                    await blobClient.UploadAsync(stream, new BlobUploadOptions { HttpHeaders = blobHttpHeader });
                }

                return Ok(new { url = blobClient.Uri.ToString() });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error during report upload: {ex.Message}");
            }
        }

        [HttpGet("recent")]
        public async Task<ActionResult<IEnumerable<object>>> GetRecentReports()
        {
            var sw = Stopwatch.StartNew();
            _logger.LogInformation("API: GetRecentReports request received.");

            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var userProfile = await _context.UserProfiles
                .Include(u => u.UserType)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.ProfileId == profileId);

            if (userProfile == null) return Unauthorized();

            bool isEmployee = userProfile.UserType?.UserTypeName == "Employee" || userProfile.Role?.RoleName == "Administrator";

            // Fetch last 5 reports created by this user
            var query = _context.DefectReports
                .AsNoTracking()
                .Include(d => d.Artwork)
                .Where(d => d.CreatedBy == userProfile.Username);

            if (!isEmployee)
            {
                query = query.Where(d => d.Artwork != null && d.Artwork.CreatedByProfileId == profileId);
            }

            var reports = await query
                .OrderByDescending(d => d.CreatedDate)
                .Take(5)
                .Select(d => new
                {
                    d.DefectReportId,
                    d.ReportName,
                    d.CreatedDate,
                    d.ReportUrl,
                    ArtworkTitle = d.Artwork != null ? d.Artwork.Title : "Unknown Artwork"
                })
                .ToListAsync();

            sw.Stop();
            _logger.LogInformation($"API: GetRecentReports completed in {sw.ElapsedMilliseconds}ms. Found {reports.Count} records.");

            return Ok(reports);
        }

        [HttpGet("search")]
        public async Task<ActionResult<IEnumerable<object>>> SearchReports([FromQuery] DateTime? fromDate, [FromQuery] DateTime? toDate, [FromQuery] string? artworkName)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            var userProfile = await _context.UserProfiles
                .Include(u => u.UserType)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.ProfileId == profileId);

            if (userProfile == null) return Unauthorized();

            bool isEmployee = userProfile.UserType?.UserTypeName == "Employee" || userProfile.Role?.RoleName == "Administrator";

            var query = _context.DefectReports
                .AsNoTracking()
                .Include(d => d.Artwork)
                .AsQueryable();

            if (!isEmployee)
            {
                query = query.Where(d => d.Artwork != null && d.Artwork.CreatedByProfileId == profileId);
            }

            if (fromDate.HasValue)
            {
                query = query.Where(d => d.CreatedDate >= fromDate.Value);
            }

            if (toDate.HasValue)
            {
                // Include the entire end date (up to midnight of the next day)
                var nextDay = toDate.Value.Date.AddDays(1);
                query = query.Where(d => d.CreatedDate < nextDay);
            }

            if (!string.IsNullOrEmpty(artworkName))
            {
                query = query.Where(d => d.Artwork != null && d.Artwork.Title.Contains(artworkName));
            }

            var reports = await query
                .OrderByDescending(d => d.CreatedDate)
                .Select(d => new
                {
                    d.DefectReportId,
                    d.ReportName,
                    d.CreatedDate,
                    d.ReportUrl,
                    ArtworkTitle = d.Artwork != null ? d.Artwork.Title : "Unknown Artwork"
                })
                .ToListAsync();

            return Ok(reports);
        }
    }
}