using SlimLib.Auth.Azure;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

partial class SlimAtpClientImpl
{
    GraphOperation<JsonDocument?> ISlimAtpSoftwareClient.GetSoftwareAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options, CancellationToken cancellationToken)
    {
        var link = BuildLink(options, $"software/{id}");

        return new(this, tenant, HttpMethod.Get, link, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpSoftwareClient.GetSoftwareDefinitionsAsync(IAzureTenant tenant, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, "software");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpSoftwareClient.GetSoftwareDistributionsAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"software/{id}/distributions");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpSoftwareClient.GetSoftwareMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"software/{id}/machineReferences");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpSoftwareClient.GetSoftwareMissingSecurityUpdatesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"software/{id}/getmissingkbs");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpSoftwareClient.GetSoftwareVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"software/{id}/vulnerabilities");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }
}