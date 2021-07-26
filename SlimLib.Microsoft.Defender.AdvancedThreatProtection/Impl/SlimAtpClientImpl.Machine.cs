using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    partial class SlimAtpClientImpl
    {
        async Task<JsonElement> ISlimAtpMachineClient.GetMachineAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options, CancellationToken cancellationToken)
        {
            var link = BuildLink(options, $"machines/{id}");

            return await GetAsync(tenant, link, new RequestHeaderOptions(), cancellationToken).ConfigureAwait(false);
        }


        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachinesAsync(IAzureTenant tenant, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, "machines");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachineLogOnUsersAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"machines/{id}/logonusers");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachineSoftwareAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"machines/{id}/software");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachineRecommendationsAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"machines/{id}/recommendations");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachineAlertsAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"machines/{id}/alerts");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpMachineClient.ListMachineVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"machines/{id}/vulnerabilities");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }
    }
}