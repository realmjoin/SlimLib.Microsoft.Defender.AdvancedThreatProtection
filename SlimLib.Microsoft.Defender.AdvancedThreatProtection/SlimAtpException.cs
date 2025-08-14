using System;
using System.Collections.Generic;
using System.Net;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class SlimAtpException : Exception
    {
        internal SlimAtpException(HttpStatusCode httpStatusCode, IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers, string graphErrorCode, string graphErrorMessage) : base(FormatErrorMessage(graphErrorCode, graphErrorMessage))
        {
            HttpStatusCode = httpStatusCode;
            Headers = headers;
            GraphErrorCode = graphErrorCode;
        }

        public HttpStatusCode HttpStatusCode { get; }
        public IEnumerable<KeyValuePair<string, IEnumerable<string>>> Headers { get; }
        public string GraphErrorCode { get; }

        private static string FormatErrorMessage(string graphErrorCode, string graphErrorMessage)
        {
            if (string.IsNullOrEmpty(graphErrorMessage))
                return graphErrorCode;

            return $"{graphErrorCode}: {graphErrorMessage}";
        }
    }
}