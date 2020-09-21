using SlimAtp.Auth;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;

namespace SlimAtp
{
    public interface ISlimAtpUserClient
    {
        IAsyncEnumerable<JsonElement> ListUserMachinesAsync(IAzureTenant tenant, string id, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}