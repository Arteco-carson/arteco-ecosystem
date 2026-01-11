using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using FineArtApi.Data;
using FineArtApi.Models;
using FineArtApi.Services;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using System.Net.Http;
using System.Text.RegularExpressions;
using System;
// Assuming you use Twilio for WhatsApp. If using Meta Direct, the payload differs slightly.

[ApiController]
[Route("api/whatsapp")]
public class WhatsAppDefectController : ControllerBase
{
    private readonly ArtContext _context;
    private readonly IAIService _aiService; // Wrapper for Gemini/GPT-4o
    private readonly IConfiguration _configuration;
    private static readonly HttpClient _httpClient = new HttpClient();

    public WhatsAppDefectController(ArtContext context, IAIService aiService, IConfiguration configuration)
    {
        _context = context;
        _aiService = aiService;
        _configuration = configuration;
    }

    [HttpPost("webhook")]
    public async Task<IActionResult> ReceiveMessage([FromForm] TwilioIncomingMessage message)
    {
        // 1. Handle Image Upload (Add Image to Report)
        if (message.NumMedia > 0 && !string.IsNullOrEmpty(message.MediaUrl0))
        {
            // Expect caption to contain "Report #123" or similar to link it
            var reportId = ParseDefectId(message.Body);
            if (reportId > 0)
            {
                var report = await _context.DefectReports.FindAsync(reportId);
                if (report != null)
                {
                    string imageUrl = await UploadMediaToAzure(message.MediaUrl0!, message.MediaContentType0 ?? "image/jpeg");
                    
                    _context.Set<DefectImage>().Add(new DefectImage
                    {
                        DefectReportId = reportId,
                        RawImageUrl = imageUrl,
                        UploadedAt = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    
                    await SendWhatsAppResponse(message.From, $"Image added to Report #{reportId}.");
                    return Ok();
                }
            }
            await SendWhatsAppResponse(message.From, "Please specify 'Report [ID]' in the caption to attach the image.");
            return Ok();
        }

        // 2. Handle Text Commands
        string cleanBody = message.Body.Trim();

        // COMMAND: Create Report [ArtworkId]
        var createMatch = Regex.Match(cleanBody, @"^create report (\d+)", RegexOptions.IgnoreCase);
        if (createMatch.Success)
        {
            if (int.TryParse(createMatch.Groups[1].Value, out int artworkId))
            {
                var artwork = await _context.Artworks.FindAsync(artworkId);
                if (artwork != null)
                {
                    var newReport = new DefectReport
                    {
                        ArtworkId = artworkId,
                        CreatedBy = message.From, // Use phone number as identifier
                        CreatedDate = DateTime.UtcNow,
                        ReportName = $"WhatsApp Report - {artwork.Title}",
                        Status = "Open",
                        ReportUrl = "Pending Generation" // Placeholder
                    };
                    _context.DefectReports.Add(newReport);
                    await _context.SaveChangesAsync();
                    await SendWhatsAppResponse(message.From, $"Report #{newReport.DefectReportId} created for '{artwork.Title}'.");
                    return Ok();
                }
            }
        }

        // COMMAND: Update Report [ReportId] [Notes]
        var updateMatch = Regex.Match(cleanBody, @"^update report (\d+) (.+)", RegexOptions.IgnoreCase);
        if (updateMatch.Success)
        {
            if (int.TryParse(updateMatch.Groups[1].Value, out int rId))
            {
                var report = await _context.DefectReports.FindAsync(rId);
                if (report != null)
                {
                    string note = updateMatch.Groups[2].Value;
                    report.AISummary = (report.AISummary + $"\n[Update]: {note}").Trim();
                    await _context.SaveChangesAsync();
                    await SendWhatsAppResponse(message.From, $"Report #{rId} updated.");
                    return Ok();
                }
            }
        }

        // COMMAND: Annotate Report [ReportId] [Note] (Adds text annotation to latest image)
        var annotateMatch = Regex.Match(cleanBody, @"^annotate report (\d+) (.+)", RegexOptions.IgnoreCase);
        if (annotateMatch.Success)
        {
             // Logic to find latest image and update metadata...
             // (Simplified for brevity: finding report and logging conversation instead)
             var rId = int.Parse(annotateMatch.Groups[1].Value);
             // Implementation would go here
        }
        
        // 3. Default / AI Logic (Existing)
        var defectId = ParseDefectId(message.Body); 
        var defect = await _context.DefectReports.FindAsync(defectId);

        if (defect == null) return Ok(); // Return 200 to satisfy webhook provider

        // 2. Log User Message
        _context.Set<DefectConversation>().Add(new DefectConversation
        {
            DefectReportId = defect.DefectReportId,
            Sender = "User",
            ExternalMessageId = message.MessageSid,
            MessageBody = message.Body
        });
        await _context.SaveChangesAsync();

        // 3. Trigger AI Pipeline
        // If the user asks for image manipulation, we send the Raw Image + Prompt to AI
        if (IsImageRequest(message.Body))
        {
            var rawImage = _context.Set<DefectImage>()
                            .Where(i => i.DefectReportId == defect.DefectReportId)
                            .OrderByDescending(i => i.UploadedAt)
                            .FirstOrDefault();

            if (rawImage != null)
            {
                // Call Gemini/OpenAI to process image
                var processedImageUrl = await _aiService.ProcessImageAsync(rawImage.RawImageUrl, message.Body);
                
                // 4. Send Response back to WhatsApp
                await SendWhatsAppResponse(message.From, "Here is the enhanced view:", processedImageUrl);
                
                // 5. Log AI Response
                _context.Set<DefectConversation>().Add(new DefectConversation
                {
                    DefectReportId = defect.DefectReportId,
                    Sender = "AI",
                    MessageBody = "Image processed based on request.",
                    MediaUrl = processedImageUrl
                });
                await _context.SaveChangesAsync();
            }
        }

        return Ok();
    }

    private async Task<string> UploadMediaToAzure(string mediaUrl, string contentType)
    {
        // Download from WhatsApp/Twilio
        var fileBytes = await _httpClient.GetByteArrayAsync(mediaUrl);
        
        // Upload to Azure
        string connectionString = _configuration["AzureStorage:ConnectionString"] ?? string.Empty;
        string containerName = _configuration["AzureStorage:ReportsContainerName"] ?? "defect-reports";
        
        var blobServiceClient = new BlobServiceClient(connectionString);
        var containerClient = blobServiceClient.GetBlobContainerClient(containerName);
        await containerClient.CreateIfNotExistsAsync(PublicAccessType.Blob);

        string ext = contentType.Contains("jpeg") ? ".jpg" : ".png";
        var fileName = $"whatsapp_{Guid.NewGuid()}{ext}";
        var blobClient = containerClient.GetBlobClient(fileName);

        using (var stream = new MemoryStream(fileBytes))
        {
            await blobClient.UploadAsync(stream, new BlobHttpHeaders { ContentType = contentType });
        }

        return blobClient.Uri.ToString();
    }

    // Helper stubs
    private int ParseDefectId(string body) 
    {
        var match = Regex.Match(body, @"report #?(\d+)", RegexOptions.IgnoreCase);
        return match.Success ? int.Parse(match.Groups[1].Value) : 0;
    }
    private bool IsImageRequest(string body) => body.ToLower().Contains("highlight") || body.ToLower().Contains("show");
    private Task SendWhatsAppResponse(string to, string text, string mediaUrl) => Task.CompletedTask; // Twilio/Meta API Call
    private Task SendWhatsAppResponse(string to, string text) => Task.CompletedTask;
}

public class TwilioIncomingMessage {
    public string Body { get; set; } = string.Empty;
    public string From { get; set; } = string.Empty;
    public string MessageSid { get; set; } = string.Empty;
    public int NumMedia { get; set; }
    public string? MediaUrl0 { get; set; }
    public string? MediaContentType0 { get; set; }
}
