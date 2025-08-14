using System;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SlimLib.Auth.Azure;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public class GraphOperation
{
    private readonly SlimAtpClientImpl client;
    private readonly IAzureTenant tenant;
    private readonly HttpMethod method;
    private readonly string requestUrl;
    private readonly InvokeRequestOptions? options;
    private readonly ReadOnlyMemory<byte> utf8Data;

    internal GraphOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options)
    {
        this.client = client;
        this.tenant = tenant;
        this.method = method;
        this.requestUrl = requestUrl;
        this.options = options;
    }

    internal GraphOperation(SlimAtpClientImpl client, IAzureTenant tenant, HttpMethod method, string requestUrl, InvokeRequestOptions? options, ReadOnlyMemory<byte> utf8Data)
    {
        this.client = client;
        this.tenant = tenant;
        this.method = method;
        this.requestUrl = requestUrl;
        this.options = options;
        this.utf8Data = utf8Data;
    }

    internal SlimAtpClientImpl Client => client;
    public IAzureTenant Tenant => tenant;
    public HttpMethod Method => method;
    public string RequestUrl => requestUrl;
    public InvokeRequestOptions? Options => options;
    public ReadOnlyMemory<byte> Utf8Data => utf8Data;

    public string[]? BatchDependsOn { get; set; }

    public TaskAwaiter GetAwaiter() => ExecuteAsync().GetAwaiter();

    public ConfiguredTaskAwaitable ConfigureAwait(bool continueOnCapturedContext) => ExecuteAsync().ConfigureAwait(continueOnCapturedContext);

    public async Task ExecuteAsync(CancellationToken cancellationToken = default)
    {
        if (Method == HttpMethod.Get)
        {
            await Client.GetAsync(Tenant, RequestUrl, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Post)
        {
            await Client.PostAsync(Tenant, RequestUrl, Utf8Data, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Patch)
        {
            await Client.PatchAsync(Tenant, RequestUrl, Utf8Data, Options, cancellationToken).ConfigureAwait(false);
        }
        else if (Method == HttpMethod.Delete)
        {
            await Client.DeleteAsync(Tenant, RequestUrl, Options, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            throw new NotSupportedException($"HTTP method {Method} is not supported for direct execution in this context.");
        }
    }

    public virtual void SetBatchResult(JsonElement jsonElement, JsonSerializerOptions? options = null) { }
    public virtual void SetBatchError(SlimAtpException exception) { }
}
