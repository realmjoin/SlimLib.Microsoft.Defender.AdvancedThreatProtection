using Microsoft.Extensions.Logging;
using SlimLib.Auth.Azure;
using System.Net.Http;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class SlimAtpClient : ISlimAtpClient
    {
        private readonly SlimAtpClientImpl impl;

        public SlimAtpClient(IAuthenticationProvider authenticationProvider, HttpClient httpClient, ILogger<SlimAtpClient> logger)
        {
            impl = new SlimAtpClientImpl(authenticationProvider, httpClient, logger);
        }

        public ISlimAtpMachineClient Machine => impl;
        public ISlimAtpUserClient User => impl;
        public ISlimAtpSoftwareClient Software => impl;
    }
}