using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FineArtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AuditLogsController : ControllerBase
    {
        private readonly ArtContext _context;

        public AuditLogsController(ArtContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<object>>> GetAuditLogs(
            [FromQuery] DateTime? dateFrom,
            [FromQuery] DateTime? dateTo,
            [FromQuery] string? performedBy,
            [FromQuery] string? entityName)
        {
            var query = from log in _context.AuditLogs
                        join user in _context.UserProfiles on log.PerformedByProfileId equals user.ProfileId into userJoin
                        from u in userJoin.DefaultIfEmpty()
                        select new { log, u };

            if (dateFrom.HasValue)
                query = query.Where(x => x.log.ChangeTimestamp >= dateFrom.Value);

            if (dateTo.HasValue)
                query = query.Where(x => x.log.ChangeTimestamp <= dateTo.Value);

            if (!string.IsNullOrEmpty(performedBy))
                query = query.Where(x => x.u != null && x.u.Username.Contains(performedBy));

            if (!string.IsNullOrEmpty(entityName))
                query = query.Where(x => x.log.TableName == entityName);

            var logs = await query
                              .OrderByDescending(x => x.log.ChangeTimestamp)
                              .Select(x => new
                              {
                                  x.log.LogId,
                                  x.log.TableName,
                                  x.log.RecordId,
                                  x.log.ActionType,
                                  PerformedBy = x.u != null ? x.u.Username : "System",
                                  x.log.ChangeTimestamp,
                                  x.log.OldValue,
                                  x.log.NewValue
                              })
                              .Take(500)
                              .ToListAsync();

            return Ok(logs);
        }
    }
}