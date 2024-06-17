using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    partial class SlimAtpClientImpl
    {
        async IAsyncEnumerable<JsonDocument> ISlimAtpUserClient.ListUserMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, $"users/{id}/machines");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }
    }
}