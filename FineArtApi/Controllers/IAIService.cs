using System.Threading.Tasks;

namespace FineArtApi.Services
{
    public interface IAIService
    {
        Task<string> ProcessImageAsync(string imageUrl, string prompt);
    }
}