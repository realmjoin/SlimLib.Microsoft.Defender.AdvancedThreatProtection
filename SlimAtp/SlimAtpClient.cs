using Microsoft.Extensions.Logging;
using SlimAtp.Auth;
using System.Net.Http;

namespace SlimAtp
{
    public class SlimAtpClient : ISlimAtpClient
    {
        private readonly SlimAtpClientImpl impl;

        public SlimAtpClient(IAuthenticationProvider authenticationProvider, HttpClient httpClient, ILogger<SlimAtpClient> logger)
        {
            impl = new SlimAtpClientImpl(authenticationProvider, httpClient, logger);
        }

        public ISlimAtpMachinesClient Devices => impl;
    }
}