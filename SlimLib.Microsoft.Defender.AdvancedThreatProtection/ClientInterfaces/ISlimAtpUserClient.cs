using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public interface ISlimAtpUserClient
    {
        IAsyncEnumerable<JsonDocument> ListUserMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}