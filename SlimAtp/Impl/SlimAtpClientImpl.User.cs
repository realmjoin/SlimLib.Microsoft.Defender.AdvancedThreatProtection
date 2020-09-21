using SlimAtp.Auth;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimAtp
{
    partial class SlimAtpClientImpl
    {
        async Task<JsonElement> ISlimAtpUserClient.GetUserAsync(IAzureTenant tenant, Guid id, ScalarRequestOptions? options, CancellationToken cancellationToken)
        {
            var link = BuildLink(options, $"users/{id}");

            return await GetAsync(tenant, link, new RequestHeaderOptions(), cancellationToken).ConfigureAwait(false);
        }

        async IAsyncEnumerable<JsonElement> ISlimAtpUserClient.ListUsersAsync(IAzureTenant tenant, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var nextLink = BuildLink(options, "users");

            await foreach (var item in GetArrayAsync(tenant, nextLink, options, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                yield return item;
            }
        }
    }
}