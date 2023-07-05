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

        private Task<JsonElement> DeleteAsync(IAzureTenant tenant, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Delete, null, requestUri, options, cancellationToken);

        private Task<JsonElement> GetAsync(IAzureTenant tenant, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Get, null, requestUri, options, cancellationToken);

        private Task<JsonElement> PatchAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Patch, utf8Data, requestUri, options, cancellationToken);

        private Task<JsonElement> PostAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Post, utf8Data, requestUri, options, cancellationToken);

        private async IAsyncEnumerable<JsonElement> GetArrayAsync(IAzureTenant tenant, string nextLink, ListRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string? link = nextLink;

            var reqOptions = new RequestHeaderOptions
            {
                ConsistencyLevelEventual = options?.ConsistencyLevelEventual ?? false,
                MaxPageSize = options?.MaxPageSize,
            };

            do
            {
                var root = await GetAsync(tenant, link, reqOptions, cancellationToken).ConfigureAwait(false);

                options?.OnPageReceived(root);

                if (link == nextLink)
                {
                    // First page
                    options?.OnMetadataReceived(root);
                }

                foreach (var item in root.GetProperty("value").EnumerateArray())
                {
                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    yield return item;
                }

                HandleNextLink(root, ref link);

            } while (link != null);
        }

        private async IAsyncEnumerable<JsonElement> PostArrayAsync(IAzureTenant tenant, ReadOnlyMemory<byte> utf8Data, string nextLink, RequestHeaderOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string? nLink = nextLink;

            do
            {
                var root = await PostAsync(tenant, utf8Data, nLink, options, cancellationToken).ConfigureAwait(false);

                foreach (var item in root.GetProperty("value").EnumerateArray())
                {
                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    yield return item;
                }

                HandleNextLink(root, ref nLink);

            } while (nLink != null);
        }

        private async Task<JsonElement> SendAsync(IAzureTenant tenant, HttpMethod method, ReadOnlyMemory<byte>? utf8Data, string requestUri, RequestHeaderOptions? options, CancellationToken cancellationToken)
        {
            using var response = await SendInternalAsync(tenant, method, utf8Data, requestUri, options, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
            {
                if (!response.IsSuccessStatusCode)
                    throw HandleError(response.StatusCode, default);

                logger.LogInformation("Got no content for HTTP request to {requestUri}.", requestUri);
                return default;
            }

            using var content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            var root = await JsonSerializer.DeserializeAsync<JsonElement>(content, cancellationToken: cancellationToken);

            if (!response.IsSuccessStatusCode)
                throw HandleError(response.StatusCode, root);

            if (root.TryGetProperty("value", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                logger.LogInformation("Got {count} items for HTTP request to {requestUri}.", items.GetArrayLength(), requestUri);
            }
            else
            {
                logger.LogInformation("Got single item for HTTP request to {requestUri}.", requestUri);
            }

            return root;
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

        private static SlimAtpException HandleError(HttpStatusCode statusCode, JsonElement root)
        {
            try
            {
                if (root.TryGetProperty("error", out var error))
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