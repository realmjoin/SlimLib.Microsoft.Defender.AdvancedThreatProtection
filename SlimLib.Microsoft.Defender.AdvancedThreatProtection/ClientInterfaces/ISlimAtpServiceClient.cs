using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection;

public interface ISlimAtpClient
{
    ISlimAtpMachineClient Machine { get; }
    ISlimAtpUserClient User { get; }
    ISlimAtpSoftwareClient Software { get; }

    Task BatchRequestAsync(IAzureTenant tenant, IList<GraphOperation> operations, CancellationToken cancellationToken = default);
}