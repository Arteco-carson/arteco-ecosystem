namespace FineArtApi.Models
{
    public class LoginRequest
    {
        // Initialising with null! to satisfy the Nullable Reference Types requirement
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}