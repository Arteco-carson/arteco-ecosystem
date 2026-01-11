using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using FineArtApi.Models;
using System.Threading.Tasks;
using FineArtApi.Services;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using System.IO;
using System.Collections.Generic;
using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class DefectImagesController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DefectImagesController> _logger;

        public DefectImagesController(ArtContext context, IAuditService auditService, IConfiguration configuration, ILogger<DefectImagesController> logger)
        {
            _context = context;
            _auditService = auditService;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadImage([FromForm] List<IFormFile> files)
        {
            try
            {
                if (files == null || files.Count == 0)
                {
                    _logger.LogWarning("DefectImagesController: No files received.");
                    return BadRequest("No files uploaded.");
                }

                _logger.LogInformation($"DefectImagesController: Received {files.Count} files.");
                var imageUrls = new List<string>();

                string connectionString = _configuration["AzureStorage:ConnectionString"] ?? string.Empty;
                // Use the specific container for reports/defects
                string containerName = _configuration["AzureStorage:ReportsContainerName"] ?? "defect-reports";

                if (string.IsNullOrEmpty(connectionString) || connectionString.Contains("YOUR_AZURE_CONNECTION_STRING"))
                {
                    return StatusCode(500, "Azure Storage connection string is not configured.");
                }

                var blobServiceClient = new BlobServiceClient(connectionString);
                var containerClient = blobServiceClient.GetBlobContainerClient(containerName);

                await containerClient.CreateIfNotExistsAsync(PublicAccessType.Blob);

                foreach (var file in files)
                {
                    _logger.LogInformation($"DefectImagesController: Processing {file.FileName}, Size: {file.Length} bytes, Type: {file.ContentType}");
                    
                    var fileName = $"defect_{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";
                    var blobClient = containerClient.GetBlobClient(fileName);

                    using (var stream = file.OpenReadStream())
                    {
                        var blobHttpHeader = new BlobHttpHeaders { ContentType = file.ContentType };
                        await blobClient.UploadAsync(stream, new BlobUploadOptions { HttpHeaders = blobHttpHeader });
                    }
                    imageUrls.Add(blobClient.Uri.ToString());
                }

                return Ok(new { imageUrls });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error during image upload: {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<ActionResult<DefectImage>> PostDefectImage(DefectImage defectImage)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            _context.Set<DefectImage>().Add(defectImage);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("DefectImages", defectImage.DefectImageId, "INSERT", profileId, null, defectImage);

            return CreatedAtAction(nameof(GetDefectImage), new { id = defectImage.DefectImageId }, defectImage);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<DefectImage>> GetDefectImage(int id)
        {
            var defectImage = await _context.Set<DefectImage>().FindAsync(id);

            if (defectImage == null)
            {
                return NotFound();
            }

            return defectImage;
        }
    }
}