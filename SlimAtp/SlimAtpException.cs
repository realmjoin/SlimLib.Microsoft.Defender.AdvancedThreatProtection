using System;
using System.Net;

namespace SlimAtp
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