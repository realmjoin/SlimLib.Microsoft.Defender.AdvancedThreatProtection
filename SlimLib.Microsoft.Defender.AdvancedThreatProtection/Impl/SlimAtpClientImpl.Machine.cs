using SlimLib.Auth.Azure;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

partial class SlimAtpClientImpl
{
    GraphOperation<JsonDocument?> ISlimAtpMachineClient.GetMachineAsync(IAzureTenant tenant, string id, ScalarRequestOptions? options, CancellationToken cancellationToken)
    {
        var link = BuildLink(options, $"machines/{id}");

        return new(this, tenant, HttpMethod.Get, link, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachinesAsync(IAzureTenant tenant, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, "machines");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachineLogOnUsersAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"machines/{id}/logonusers");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachineSoftwareAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"machines/{id}/software");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachineRecommendationsAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"machines/{id}/recommendations");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachineAlertsAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"machines/{id}/alerts");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }

    GraphArrayOperation<JsonDocument> ISlimAtpMachineClient.GetMachineVulnerabilitiesAsync(IAzureTenant tenant, string id, ListRequestOptions? options, CancellationToken cancellationToken)
    {
        var nextLink = BuildLink(options, $"machines/{id}/vulnerabilities");

        return new(this, tenant, HttpMethod.Get, nextLink, options, default, static doc => doc);
    }
}