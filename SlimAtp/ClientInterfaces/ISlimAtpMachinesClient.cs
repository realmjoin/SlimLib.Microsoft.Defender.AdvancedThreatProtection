using SlimAtp.Auth;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SlimAtp
{
    public interface ISlimAtpMachinesClient
    {
        Task<JsonElement> GetMachineAsync(IAzureTenant tenant, Guid deviceID, ScalarRequestOptions? options = default, CancellationToken cancellationToken = default);

        IAsyncEnumerable<JsonElement> GetMachinesAsync(IAzureTenant tenant, ListRequestOptions? options = default, CancellationToken cancellationToken = default);
    }
}