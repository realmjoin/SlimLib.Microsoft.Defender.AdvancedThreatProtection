using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public interface ISlimAtpSoftwareClient
    {
        Task<JsonElement> GetSoftwareAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonElement> ListSoftwareAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonElement> ListSoftwareDistributionsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListSoftwareMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListSoftwareMissingSecurityUpdatesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListSoftwareVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}