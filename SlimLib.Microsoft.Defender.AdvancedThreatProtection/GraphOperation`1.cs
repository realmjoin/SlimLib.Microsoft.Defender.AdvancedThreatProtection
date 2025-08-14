using System;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SlimLib.Auth.Azure;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public class GraphOperation<T> : GraphOperation
{
    private readonly Func<JsonDocument, T> executeFunc;

    private T? result;

    public T? Result
    {
        get => Error is null ? result : throw Error;
    }

    public SlimAtpException? Error { get; private set; }

    internal GraphOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options, Func<JsonDocument, T> executeFunc) : this(client, tenant, method, requestUrl, options, default, executeFunc)
    {
    }

    internal GraphOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options, ReadOnlyMemory<byte> utf8Data, Func<JsonDocument, T> executeFunc) : base(client, tenant, method, requestUrl, options, utf8Data)
    {
        this.executeFunc = executeFunc;
    }

    public new TaskAwaiter<T?> GetAwaiter() => ExecuteAsync().GetAwaiter();

    public new ConfiguredTaskAwaitable<T?> ConfigureAwait(bool continueOnCapturedContext) => ExecuteAsync().ConfigureAwait(continueOnCapturedContext);

    public new async Task<T?> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        JsonDocument? doc;

        if (Method == HttpMethod.Get)
        {
            doc = await Client.GetAsync(Tenant, RequestUrl, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Post)
        {
            doc = await Client.PostAsync(Tenant, RequestUrl, Utf8Data, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Patch)
        {
            doc = await Client.PatchAsync(Tenant, RequestUrl, Utf8Data, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Delete)
        {
            await Client.DeleteAsync(Tenant, RequestUrl, Options, cancellationToken).ConfigureAwait(false);
            doc = null;
        }
        else
        {
            throw new NotSupportedException($"HTTP method {Method} is not supported for direct execution in this context.");
        }

        if (doc is null)
        {
            return default;
        }

        result = executeFunc(doc);
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