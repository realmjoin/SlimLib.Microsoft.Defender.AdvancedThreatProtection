using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public interface ISlimAtpSoftwareClient
    {
        Task<JsonDocument?> GetSoftwareAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonDocument> ListSoftwareAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonDocument> ListSoftwareDistributionsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonDocument> ListSoftwareMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonDocument> ListSoftwareMissingSecurityUpdatesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonDocument> ListSoftwareVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}