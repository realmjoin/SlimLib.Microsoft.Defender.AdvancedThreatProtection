using SlimLib.Auth.Azure;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

partial class SlimAtpClientImpl
{
    GraphArrayOperation<JsonDocument> ISlimAtpUserClient.GetUserMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"users/{id}/machines");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }
}