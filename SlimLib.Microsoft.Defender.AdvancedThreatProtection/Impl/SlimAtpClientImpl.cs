using Microsoft.Extensions.Logging;
using SlimLib.Auth.Azure;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    internal sealed partial class SlimAtpClientImpl : SlimODataClientBase, ISlimAtpMachineClient, ISlimAtpUserClient, ISlimAtpSoftwareClient
    {
        public SlimAtpClientImpl(IAuthenticationProvider authenticationProvider, HttpClient httpClient, ILogger<SlimAtpClient> logger)
            : base(authenticationProvider, httpClient, logger)
        {
        }

        protected override string Scope => SlimAtpConstants.ScopeDefault;

#pragma warning disable CS0618 // SlimAtpException is intentionally thrown for backward compatibility

        protected override SlimApiException CreateApiError(HttpStatusCode statusCode, IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers, string errorCode, string errorMessage)
            => new SlimAtpException(statusCode, headers, errorCode, errorMessage);

#pragma warning restore CS0618
    }
}