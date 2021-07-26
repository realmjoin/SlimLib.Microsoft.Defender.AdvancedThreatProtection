using System;
using System.Net;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class SlimAtpException : Exception
    {
        internal SlimAtpException(HttpStatusCode httpStatusCode, string? errorCode, string? errorMessage) : base(errorMessage)
        {
            HttpStatusCode = httpStatusCode;
            ErrorCode = errorCode;
        }

        public HttpStatusCode HttpStatusCode { get; }
        public string? ErrorCode { get; }
    }
}