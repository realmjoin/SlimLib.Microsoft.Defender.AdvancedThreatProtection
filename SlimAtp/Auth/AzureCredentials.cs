using System.Collections.Generic;

namespace SlimAtp.Auth
{
    public abstract class AzureCredentials : IAzureCredentials
    {
        public abstract IDictionary<string, string> GetRequestData(string scope);
    }
}