using System;
using System.Net;

namespace SlimAtp.Auth
{
    public class AuthException : Exception
    {
        internal AuthException(HttpStatusCode httpStatusCode, string azureADErrorCode, string azureADErrorMessage) : base(azureADErrorMessage)
        {
            HttpStatusCode = httpStatusCode;
            AzureADErrorCode = azureADErrorCode;
        }

        public HttpStatusCode HttpStatusCode { get; }
        public string AzureADErrorCode { get; }
    }
}