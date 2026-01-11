namespace FineArtApi.Models
{
    public class RegistrationRequest
    {
        // Initialising with null! resolves CS8618 warnings for DTOs
        public string FirstName { get; set; } = null!;
        
        public string LastName { get; set; } = null!;
        
        public string Username { get; set; } = null!;
        
        public string Email { get; set; } = null!;
        
        public string Password { get; set; } = null!;
        
        // Required for SQL UNIQUE constraint in UserProfiles table
        public string ExternalUserId { get; set; } = null!;

        public string UserRole { get; set; } = "Guest";
        
        public bool MarketingConsent { get; set; }
    }
}