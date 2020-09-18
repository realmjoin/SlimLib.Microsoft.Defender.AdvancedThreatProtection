using Microsoft.Extensions.Caching.Memory;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

namespace SlimAtp.Auth
{
    public class AzureAuthenticationClient : IAuthenticationProvider
    {
        private const int MinTokenLifetimeSeconds = 300;

        private readonly IAzureCredentials azureCredentials;
        private readonly HttpClient httpClient;
        private readonly IMemoryCache? memoryCache;

        public AzureAuthenticationClient(IAzureCredentials azureCredentials, HttpClient httpClient, IMemoryCache? memoryCache = null)
        {
            this.azureCredentials = azureCredentials;
            this.httpClient = httpClient;
            this.memoryCache = memoryCache;
        }

        public async Task AuthenticateRequestAsync(IAzureTenant tenant, string scope, HttpRequestMessage request)
        {
            var auth = await GetAuthenticationAsync(tenant, scope);

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.AccessToken);
        }

        public Task<AuthSuccessResponse> GetAuthenticationAsync(IAzureTenant tenant, string scope)
        {
            if (memoryCache != null)
            {
                var key = nameof(AzureAuthenticationClient) + nameof(GetAuthenticationAsync) + tenant.Identifier + scope;

                return memoryCache.GetOrCreateAsync(key, async entry =>
                {
                    var response = await GetAuthenticationImplAsync(tenant, scope);

                    entry.SetAbsoluteExpiration(TimeSpan.FromSeconds(response.ExpiresIn - MinTokenLifetimeSeconds));

                    return response;
                });
            }

            return GetAuthenticationImplAsync(tenant, scope);
        }

        private async Task<AuthSuccessResponse> GetAuthenticationImplAsync(IAzureTenant tenant, string scope)
        {
            var data = azureCredentials.GetRequestData(scope);

            using var content = new FormUrlEncodedContent(data);
            using var response = await httpClient.PostAsync(tenant.TokenUrl, content).ConfigureAwait(false);
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var error = await JsonSerializer.DeserializeAsync<AuthErrorResponse>(stream).ConfigureAwait(false);
                throw new AuthException(response.StatusCode, error.Error ?? "No more details available.", error.ErrorDescription ?? "No more details available.");
            }

            return await JsonSerializer.DeserializeAsync<AuthSuccessResponse>(stream).ConfigureAwait(false);
        }
    }
}