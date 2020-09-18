using System;
using System.Net;

namespace SlimAtp
{
    public class SlimAtpException : Exception
    {
        internal SlimAtpException(HttpStatusCode httpStatusCode, string graphErrorCode, string graphErrorMessage) : base(graphErrorMessage)
        {
            HttpStatusCode = httpStatusCode;
            GraphErrorCode = graphErrorCode;
        }

        public HttpStatusCode HttpStatusCode { get; }
        public string GraphErrorCode { get; }
    }
}