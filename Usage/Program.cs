using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Polly;
using SlimAtp;
using SlimAtp.Auth;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Usage
{
    public class Program
    {
        public static IConfigurationRoot? Configuration { get; private set; }

        public static async Task Main(string[] args)
        {
            var builder = new ConfigurationBuilder();
            builder.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            builder.AddUserSecrets<Program>();

            Configuration = builder.Build();

            var services = new ServiceCollection();

            services.AddLogging(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("SlimAtp", LogLevel.Trace)
                    .AddConsole();
            });

            var tenant = new AzureTenant(Configuration.GetValue<string>("Tenant"));
            var clientCredentials = new AzureClientCredentials();
            Configuration.GetSection("AzureAD").Bind(clientCredentials);

            services.AddMemoryCache();
            services.AddTransient<IAuthenticationProvider>(sp => new AzureAuthenticationClient(clientCredentials, sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(AzureAuthenticationClient)), sp.GetService<IMemoryCache>()));
            services.AddHttpClient<ISlimAtpClient, SlimAtpClient>(client => client.BaseAddress = new Uri(SlimAtpConstants.Endpoint)).AddTransientHttpErrorPolicy(p => p.WaitAndRetryAsync(3, _ => TimeSpan.FromMilliseconds(500)));

            var container = services.BuildServiceProvider();

            using (var scope = container.CreateScope())
            {
                var client = scope.ServiceProvider.GetRequiredService<ISlimAtpClient>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

                var count = 0;
                await foreach (var item in client.Devices.GetMachinesAsync(tenant))
                {
                    // Since $top = 10 is set, each page will have at most 10 items. This means GetMachinesAsync will execute two HTTP calls.
                    logger.LogInformation("Got {fn} item: {id}", nameof(client.Devices.GetMachinesAsync), item.GetRawText());
                    if (++count >= 20) break;
                }
            }
        }
    }
}
