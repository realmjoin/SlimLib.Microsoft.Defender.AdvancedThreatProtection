using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Polly;
using SlimLib.Auth.Azure;
using SlimLib.Microsoft.Defender.AdvancedThreatProtection;
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
                    .AddFilter("System.Net.Http.HttpClient", LogLevel.Information)
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

                // This ctor is a helper for getting the new metadata.
                // See: https://developer.microsoft.com/en-us/identity/blogs/build-advanced-queries-with-count-filter-search-and-orderby/
                var options = new ListRequestOptions(Options_MetadataReceived) { MaxPageSize = 2, Top = 4 };

                void Options_MetadataReceived(object? sender, MetadataEventArgs e)
                {
                    logger.LogInformation($"Metadata received: {(e.Context, e.Count)}");
                }

                var count = 0;
                await foreach (var item in client.Machine.ListMachinesAsync(tenant, options))
                {
                    count++;

                    // MaxPageSize = 2 is set, each page will have at most 2 items.
                    // Top = 4 is set, the server SHOULD stop after 2 pages.
                    logger.LogInformation("Got item {count}: {json}", count, item.GetRawText());
                    if (count >= options.Top) break;
                }
            }

            // Wait for log messages to flush
            await Task.Delay(100);
        }
    }
}
