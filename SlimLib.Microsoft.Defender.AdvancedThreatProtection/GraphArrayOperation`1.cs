using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SlimLib.Auth.Azure;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public class GraphArrayOperation<T> : GraphOperation
{
    private readonly InvokeRequestOptions? options;
    private readonly Func<JsonDocument, T> executeFunc;

    private T? result;

    public T? Result
    {
        get => Error is null ? result : throw Error;
    }

    public SlimAtpException? Error { get; private set; }

    internal GraphArrayOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options, Func<JsonDocument, T> executeFunc) : this(client, tenant, method, requestUrl, options, default, executeFunc)
    {
    }

    internal GraphArrayOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options, ReadOnlyMemory<byte> utf8Data, Func<JsonDocument, T> executeFunc) : base(client, tenant, method, requestUrl, options, utf8Data)
    {
        this.options = options;
        this.executeFunc = executeFunc;
    }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default) => GetDataAsync(RequestUrl, cancellationToken);

    public async IAsyncEnumerator<T> GetDataAsync(string requestUrl, CancellationToken cancellationToken = default)
    {
        if (Method == HttpMethod.Get)
        {
            await foreach (var item in Client.GetArrayAsync(Tenant, requestUrl, options, cancellationToken))
            {
                yield return executeFunc(item);
            }

            yield break;
        }
        else if (Method == HttpMethod.Post)
        {
            var doc = await Client.PostAsync(Tenant, requestUrl, Utf8Data, options, cancellationToken).ConfigureAwait(false);
            if (doc is not null)
            {
                yield return executeFunc(doc);
            }

            yield break;
        }
        else if (Method == HttpMethod.Patch)
        {
            var doc = await Client.PatchAsync(Tenant, requestUrl, Utf8Data, options, cancellationToken).ConfigureAwait(false);
            if (doc is not null)
            {
                yield return executeFunc(doc);
            }

            yield break;
        }
        else if (Method == HttpMethod.Delete)
        {
            await Client.DeleteAsync(Tenant, requestUrl, options, cancellationToken).ConfigureAwait(false);
            yield break;
        }

        throw new NotSupportedException($"HTTP method {Method} is not supported for direct execution in this context.");
    }

    public async Task<T?> GetNextPageAsync(string? nextLink, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(nextLink)) return default;

        var operation = new GraphOperation<T>(Client, Tenant, Method, nextLink, options, executeFunc);

        result = await operation.ExecuteAsync(cancellationToken).ConfigureAwait(false);

        return result;
    }

    public override void SetBatchResult(JsonElement jsonElement, JsonSerializerOptions? options = null)
    {
        result = jsonElement.Deserialize<T>(options);
    }

    public override void SetBatchError(SlimAtpException exception)
    {
        Error = exception;
    }
}
