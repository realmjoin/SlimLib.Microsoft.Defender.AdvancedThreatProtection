using SlimLib.Auth.Azure;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public interface ISlimAtpSoftwareClient
{
    GraphOperation<JsonDocument?> GetSoftwareAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

    GraphArrayOperation<JsonDocument> GetSoftwareDefinitionsAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);

    GraphArrayOperation<JsonDocument> GetSoftwareDistributionsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetSoftwareMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetSoftwareMissingSecurityUpdatesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetSoftwareVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
}