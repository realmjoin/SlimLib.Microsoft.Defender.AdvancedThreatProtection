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
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    internal sealed partial class SlimAtpClientImpl : ISlimHttpClient, ISlimAtpMachineClient, ISlimAtpUserClient, ISlimAtpSoftwareClient
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

        internal async Task DeleteAsync(IAzureTenant tenant, string requestUri, InvokeRequestOptions? options, CancellationToken cancellationToken)
        {
            using var doc = await SendAsync(tenant, HttpMethod.Delete, requestUri, null, options, null, cancellationToken).ConfigureAwait(false);
        }

        internal Task<JsonDocument?> GetAsync(IAzureTenant tenant, string requestUri, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Get, requestUri, null, options, null, cancellationToken);

        internal Task<JsonDocument?> PatchAsync(IAzureTenant tenant, string requestUri, ReadOnlyMemory<byte> utf8Data, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Patch, requestUri, utf8Data, options, null, cancellationToken);

        internal Task<JsonDocument?> PostAsync(IAzureTenant tenant, string requestUri, ReadOnlyMemory<byte> utf8Data, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => SendAsync(tenant, HttpMethod.Post, requestUri, utf8Data, options, null, cancellationToken);

        internal async IAsyncEnumerable<JsonDocument> GetArrayAsync(IAzureTenant tenant, string nextLink, InvokeRequestOptions? options, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string? link = nextLink;

            do
            {
                var doc = await GetAsync(tenant, link, options, cancellationToken).ConfigureAwait(false);

                if (doc is not null)
                {
                    HandleNextLink(doc.RootElement, ref link);
                    yield return doc;
                }

            } while (link != null);
        }

        public async Task BatchRequestAsync(IAzureTenant tenant, IList<GraphOperation> operations, CancellationToken cancellationToken)
        {
            var requests = new JsonArray();

            var payload = new JsonObject
            {
                ["requests"] = requests
            };

            var i = 0;

            foreach (var operation in operations)
            {
                var request = new JsonObject
                {
                    ["id"] = i++.ToString(),
                    ["method"] = operation.Method.ToString(),
                    ["url"] = operation.RequestUrl,
                };

                if (operation.DependsOn is not null)
                {
                    request["dependsOn"] = JsonSerializer.SerializeToNode(operation.DependsOn);
                }

                operation.Options?.ConfigureBatchRequest(request);

                requests.Add(request);
            }

            using var response = await PostAsync(tenant, "$batch", JsonSerializer.SerializeToUtf8Bytes(payload), options: null, cancellationToken) ?? throw new InvalidOperationException("Batch request failed.");

            if (response.RootElement.TryGetProperty("responses", out var responses) && responses is { ValueKind: JsonValueKind.Array })
            {
                for (var j = 0; j < requests.Count; j++)
                {
                    var item = responses.EnumerateArray().FirstOrDefault(x => x.TryGetProperty("id", out var id) && id.GetString() == j.ToString());

                    var error = HandleBatchError(item);

                    if (error is not null)
                    {
                        operations[j].SetBatchError(error);
                    }
                    else if (item.TryGetProperty("body", out var body))
                    {
                        operations[j].SetResultBatch(body);
                    }
                }

                return;
            }

            throw new InvalidOperationException("Batch request failed.");
        }

        private async Task<JsonDocument?> SendAsync(IAzureTenant tenant, HttpMethod method, string requestUri, ReadOnlyMemory<byte>? utf8Data, InvokeRequestOptions? options, Func<HttpResponseMessage, Task>? httpResponseMessageCustomResponseHandler, CancellationToken cancellationToken)
        {
            using var response = await SendInternalAsync(tenant, method, requestUri, utf8Data, options, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
            {
                logger.LogInformation("Got no content for HTTP request to {requestUri}.", requestUri);
                if (httpResponseMessageCustomResponseHandler != null)
                {
                    await httpResponseMessageCustomResponseHandler(response);
                }
                return null;
            }

            if (httpResponseMessageCustomResponseHandler != null)
            {
                await httpResponseMessageCustomResponseHandler(response);
            }

            using var content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            var doc = await JsonSerializer.DeserializeAsync<JsonDocument>(content, cancellationToken: cancellationToken);

            if (!response.IsSuccessStatusCode)
                throw HandleError(response.StatusCode, response.Headers, doc);

            return doc;
        }

        private async Task<HttpResponseMessage> SendInternalAsync(IAzureTenant tenant, HttpMethod method, string requestUri, ReadOnlyMemory<byte>? utf8Data, InvokeRequestOptions? options, CancellationToken cancellationToken)
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

            options?.ConfigureHttpRequest(request);

            return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private static SlimAtpException HandleError(HttpStatusCode statusCode, IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers, JsonDocument? root)
        {
            try
            {
                if (root?.RootElement.TryGetProperty("error", out var error) == true)
                {
                    return new SlimAtpException(statusCode, headers, error.GetProperty("code").GetString() ?? "", error.GetProperty("message").GetString() ?? "");
                }
            }
            catch
            {
            }

            return new SlimAtpException(0, [], "Unkown error", "");
        }

        private static SlimAtpException? HandleBatchError(JsonElement item)
        {
            if (item is not { ValueKind: JsonValueKind.Object })
                return null;

            if (item.TryGetProperty("status", out var status) && status is { ValueKind: JsonValueKind.Number })
            {
                var http = (HttpStatusCode)status.GetInt32();

                if (http == HttpStatusCode.OK)
                    return null;

                if (item.TryGetProperty("body", out var body) && body is { ValueKind: JsonValueKind.Object })
                {
                    if (body.TryGetProperty("error", out var error))
                    {
                        var headers = new List<KeyValuePair<string, IEnumerable<string>>>();

                        if (item.TryGetProperty("headers", out var headersElement) && headersElement is { ValueKind: JsonValueKind.Object })
                        {
                            foreach (var header in headersElement.EnumerateObject())
                            {
                                var values = new List<string>();

                                if (header.Value.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var value in header.Value.EnumerateArray())
                                    {
                                        if (value.ValueKind == JsonValueKind.String)
                                        {
                                            var str = value.GetString();

                                            if (str is not null)
                                                values.Add(str);
                                        }
                                    }
                                }
                                else if (header.Value.ValueKind == JsonValueKind.String)
                                {
                                    var str = header.Value.GetString();

                                    if (str is not null)
                                        values.Add(str);
                                }

                                if (values.Count > 0)
                                    headers.Add(new(header.Name, values));
                            }
                        }

                        if (error is { ValueKind: JsonValueKind.Object })
                            return new(http, headers, error.GetProperty("code").GetString() ?? "", error.GetProperty("message").GetString() ?? "");
                        else
                            return new(http, headers, "Unkown error", "");
                    }
                }
            }

            return null;
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

        Task<JsonDocument?> ISlimHttpClient.GetAsync(IAzureTenant tenant, string requestUri, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => GetAsync(tenant, requestUri, options, cancellationToken);

        Task<JsonDocument?> ISlimHttpClient.PostAsync(IAzureTenant tenant, string requestUri, ReadOnlyMemory<byte> utf8Data, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => PostAsync(tenant, requestUri, utf8Data, options, cancellationToken);

        Task<JsonDocument?> ISlimHttpClient.PatchAsync(IAzureTenant tenant, string requestUri, ReadOnlyMemory<byte> utf8Data, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => PatchAsync(tenant, requestUri, utf8Data, options, cancellationToken);

        Task ISlimHttpClient.DeleteAsync(IAzureTenant tenant, string requestUri, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => DeleteAsync(tenant, requestUri, options, cancellationToken);

        IAsyncEnumerable<JsonDocument> ISlimHttpClient.GetArrayAsync(IAzureTenant tenant, string requestUri, InvokeRequestOptions? options, CancellationToken cancellationToken)
            => GetArrayAsync(tenant, requestUri, options, cancellationToken);
    }
}