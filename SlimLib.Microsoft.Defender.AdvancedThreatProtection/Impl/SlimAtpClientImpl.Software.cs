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
        async Task<JsonElement> ISlimAtpSoftwareClient.GetSoftwareAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options, CancellationToken cancellationToken)
        {
            var link = BuildLink(options, $"software/{id}");

            return await GetAsync(tenant, link, new RequestHeaderOptions(), cancellationToken).ConfigureAwait(false);
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpSoftwareClient.ListSoftwareAsync(IAzureTenant tenant, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, "software");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }
    }
}