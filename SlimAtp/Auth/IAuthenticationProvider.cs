using System.Net.Http;
using System.Threading.Tasks;

namespace SlimAtp.Auth
{
    public interface IAuthenticationProvider
    {
        Task AuthenticateRequestAsync(IAzureTenant tenant, string scope, HttpRequestMessage request);
    }
}