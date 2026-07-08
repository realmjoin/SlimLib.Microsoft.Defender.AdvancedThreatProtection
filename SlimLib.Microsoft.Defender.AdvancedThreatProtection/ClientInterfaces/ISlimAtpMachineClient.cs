using SlimLib.Auth.Azure;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public interface ISlimAtpMachineClient
{
    GraphOperation<JsonDocument?> GetMachineAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

    GraphArrayOperation<JsonDocument> GetMachinesAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);

    GraphArrayOperation<JsonDocument> GetMachineLogOnUsersAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetMachineSoftwareAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetMachineRecommendationsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetMachineAlertsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    GraphArrayOperation<JsonDocument> GetMachineVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
}