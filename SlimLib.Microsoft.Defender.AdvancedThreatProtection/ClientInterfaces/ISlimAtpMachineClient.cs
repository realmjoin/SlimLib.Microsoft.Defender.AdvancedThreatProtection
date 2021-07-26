using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public interface ISlimAtpMachineClient
    {
        Task<JsonElement> GetMachineAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonElement> ListMachinesAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListMachineLogOnUsersAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListMachineSoftwareAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListMachineRecommendationsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListMachineAlertsAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
        IAsyncEnumerable<JsonElement> ListMachineVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}