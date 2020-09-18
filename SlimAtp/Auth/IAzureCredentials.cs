using System.Collections.Generic;

namespace SlimAtp.Auth
{
    public interface IAzureCredentials
    {
        IDictionary<string, string> GetRequestData(string scope);
    }
}