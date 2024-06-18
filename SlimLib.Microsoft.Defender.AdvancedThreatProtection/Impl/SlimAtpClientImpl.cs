using Microsoft.Extensions.Logging;
using SlimLib.Auth.Azure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    internal sealed partial class SlimAtpClientImpl : ISlimAtpMachineClient, ISlimAtpUserClient, ISlimAtpSoftwareClient
    {
        private readonly IAuthenticationProvider authenticationProvider;
        private readonly HttpClient httpClient;
        private readonly ILogger<SlimAtpClient> logger;

        public SlimAtpClientImpl(IAuthenticationProvider authenticationProvider, HttpClient httpClient, ILogger<SlimAtpClient> logger)
        {
            this.authenticationProvider = authenticationProvider;
            this.httpClient = httpClient;
            this.logger = logger;
        }

        private async Task DeleteAsync(IAzureTenant tenant, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
        {
            using var doc = await SendAsync(tenant, HttpMethod.Delete, null, requestUri, options, cancellationToken).ConfigureAwait(false);
        }

        private Task<JsonDocument?> GetAsync(IAzureTenant tenant, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Get, null, requestUri, options, cancellationToken);

        private Task<JsonDocument?> PatchAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Patch, utf8Data, requestUri, options, cancellationToken);

        private Task<JsonDocument?> PostAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Post, utf8Data, requestUri, options, cancellationToken);

        private async IAsyncEnumerable<JsonDocument> GetArrayAsync(IAzureTenant tenant, string nextLink, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string? link = nextLink;

            var reqOptions = new RequestHeaderOptions { ConsistencyLevelEventual = options?.ConsistencyLevelEventual ?? false };

            do
            {
                var doc = await GetAsync(tenant, link, reqOptions, cancellationToken).ConfigureAwait(false);

                if (doc is not null)
                {
                    HandleNextLink(doc.RootElement, ref link);
                    yield return doc;
                }

            } while (link != null);
        }

        private async IAsyncEnumerable<JsonDocument> PostArrayAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string nextLink, RequestHeaderOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string? link = nextLink;

            do
            {
                var doc = await PostAsync(tenant, utf8Data, link, options, cancellationToken).ConfigureAwait(false);

                if (doc is not null)
                {
                    HandleNextLink(doc.RootElement, ref link);
                    yield return doc;
                }

            } while (link != null);
        }

        private async Task<JsonDocument?> SendAsync(IAzureTenant tenant, HttpMethod method, ReadOnlyMemory<byte>? utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
        {
            using var response = await SendInternalAsync(tenant, method, utf8Data, requestUri, options, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
            {
                logger.LogInformation("Got no content for HTTP request to {requestUri}.", requestUri);
                return null;
            }

            using var content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            var doc = await JsonSerializer.DeserializeAsync<JsonDocument>(content, cancellationToken: cancellationToken);

            if (!response.IsSuccessStatusCode)
                throw HandleError(response.StatusCode, response.Headers, doc);

            return doc;
        }

        private async Task<HttpResponseMessage> SendInternalAsync(IAzureTenant tenant, HttpMethod method, ReadOnlyMemory<byte>? utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(method, requestUri);

            if (utf8Data != null)
            {
                request.Content = new ReadOnlyMemoryContent(utf8Data.Value)
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("application/json") { CharSet = Encoding.UTF8.WebName } }
                };
            }

            await authenticationProvider.AuthenticateRequestAsync(tenant, SlimAtpConstants.ScopeDefault, request).ConfigureAwait(false);

            if (options?.ConsistencyLevelEventual == true)
            {
                logger.LogDebug("Setting HTTP header ConsistencyLevel: eventual");
                request.Headers.Add("ConsistencyLevel", "eventual");
            }

            if (options?.Return > ReturnOptions.Unspecified)
            {
                logger.LogDebug("Setting HTTP header Prefer: return=" + options.Return.ToString().ToLowerInvariant());
                request.Headers.Add("Prefer", "return=" + options.Return.ToString().ToLowerInvariant());
            }

            if (options?.MaxPageSize >= 0)
            {
                logger.LogDebug("Setting HTTP header Prefer: maxpagesize=" + options.MaxPageSize);
                request.Headers.Add("Prefer", "maxpagesize=" + options.MaxPageSize);
            }

            return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private static SlimAtpException HandleError(HttpStatusCode statusCode, HttpResponseHeaders headers, JsonDocument? root)
        {
            try
            {
                if (root?.RootElement.TryGetProperty("error", out var error) == true)
                {
                    return new SlimAtpException(statusCode, error.GetProperty("code").GetString(), error.GetProperty("message").GetString());
                }
            }
            catch
            {
            }

            return new SlimAtpException(statusCode, "Unkown error", "Unkown error");
        }

        private static void HandleNextLink(JsonElement root, ref string? nextLink)
        {
            if (root.TryGetProperty("@odata.nextLink", out var el))
            {
                nextLink = el.GetString();
            }
            else
            {
                nextLink = null;
            }
        }

        private string BuildLink(ScalarRequestOptions? options, string call)
        {
            var args = new List<string>();

            if (options?.Select.Count > 0)
                args.Add("$select=" + Uri.EscapeDataString(string.Join(",", options.Select)));

            if (options?.Expand != null)
                args.Add("$expand=" + Uri.EscapeDataString(options.Expand));

            return RequestOptions.BuildLink(call, args);
        }

        private string BuildLink(ListRequestOptions? options, string call)
        {
            var args = new List<string>();

            if (options?.Select.Count > 0)
                args.Add("$select=" + Uri.EscapeDataString(string.Join(",", options.Select)));

            if (options?.Filter != null)
                args.Add("$filter=" + Uri.EscapeDataString(options.Filter));

            if (options?.Search != null)
                args.Add("$search=" + Uri.EscapeDataString(options.Search));

            if (options?.Expand != null)
                args.Add("$expand=" + Uri.EscapeDataString(options.Expand));

            if (options?.OrderBy.Count > 0)
                args.Add("$orderby=" + Uri.EscapeDataString(string.Join(",", options.OrderBy)));

            if (options?.Count != null)
                args.Add("$count=" + (options.Count.Value ? "true" : "false"));

            if (options?.Skip != null)
                args.Add("$skip=" + options.Skip);

            if (options?.Top != null)
                args.Add("$top=" + options.Top);

            return RequestOptions.BuildLink(call, args);
        }

        private string BuildLink(InvokeRequestOptions? options, string call)
        {
            return RequestOptions.BuildLink(call, Enumerable.Empty<string>());
        }
    }
}