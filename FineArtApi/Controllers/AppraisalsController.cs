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
    [Authorize] // Senior Management Compliance: Ensuring financial privacy
    public class AppraisalsController : ControllerBase
    {
        private readonly ArtContext _context;
        private readonly IAuditService _auditService;

        public AppraisalsController(ArtContext context, IAuditService auditService)
        {
            _context = context;
            _auditService = auditService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<object>>> GetAppraisals()
        {
            // Extract the ProfileId from the JWT Token claims
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("id") ?? User.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int profileId))
            {
                return Unauthorized(new { message = "Security Identity missing or invalid." });
            }

            // Filter logic: Only return appraisals for artworks owned by this user profile
            return await _context.Appraisals
                .Include(a => a.Artwork)
                .Where(a => a.Artwork != null && a.Artwork.CreatedByProfileId == profileId) 
                .OrderByDescending(a => a.ValuationDate) 
                .Select(a => new {
                    a.AppraisalId,
                    a.ArtworkId,
                    // Fixed CS8602: Safe navigation for Title
                    ArtworkTitle = a.Artwork != null ? a.Artwork.Title : "Unassigned Asset",
                    a.ValuationAmount,
                    a.CurrencyCode,
                    a.ValuationDate,
                    a.AppraiserName,
                    a.InsuranceValue,
                    a.Notes
                })
                .ToListAsync();
        }

        [HttpPost]
        public async Task<ActionResult<Appraisal>> PostAppraisal(Appraisal appraisal)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Unauthorized();
            
            int profileId = int.Parse(userIdClaim.Value);

            // Validation: Ensure the user owns the artwork they are attempting to appraise
            var artwork = await _context.Artworks.FindAsync(appraisal.ArtworkId);
            
            if (artwork == null || artwork.CreatedByProfileId != profileId)
            {
                return Unauthorized(new { message = "You can only record valuations for assets in your own collection." });
            }

            // Snapshot old artwork state for audit
            var oldArtworkState = new { artwork.AcquisitionCost, artwork.AcquisitionDate, artwork.LastModifiedAt };

            // Automatically update the Artwork's valuation details
            artwork.AcquisitionCost = appraisal.ValuationAmount;
            artwork.AcquisitionDate = appraisal.ValuationDate;
            artwork.LastModifiedAt = System.DateTime.UtcNow;

            _context.Appraisals.Add(appraisal);
            await _context.SaveChangesAsync();

            // Log the actions
            await _auditService.LogAsync("Appraisals", appraisal.AppraisalId, "INSERT", profileId, null, appraisal);
            await _auditService.LogAsync("Artworks", artwork.ArtworkId, "UPDATE", profileId, oldArtworkState, new { artwork.AcquisitionCost, artwork.AcquisitionDate, artwork.LastModifiedAt });

            return CreatedAtAction(nameof(GetAppraisals), new { id = appraisal.AppraisalId }, appraisal);
        }
    }
}