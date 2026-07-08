using System;
using System.Collections.Generic;
using System.Net;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    [Obsolete("Use SlimApiException from SlimLib.Auth.Azure instead.")]
    public class SlimAtpException : SlimApiException
    {
        internal SlimAtpException(HttpStatusCode httpStatusCode, IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers, string graphErrorCode, string graphErrorMessage)
            : base(httpStatusCode, headers, graphErrorCode, graphErrorMessage)
        {
        }

        [Obsolete("Use ErrorCode instead.")]
        public string GraphErrorCode => ErrorCode;
    }
}