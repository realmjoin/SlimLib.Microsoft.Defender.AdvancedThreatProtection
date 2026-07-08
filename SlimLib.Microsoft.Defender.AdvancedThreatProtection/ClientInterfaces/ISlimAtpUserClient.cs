using SlimLib.Auth.Azure;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public interface ISlimAtpUserClient
{
    GraphArrayOperation<JsonDocument> GetUserMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
}