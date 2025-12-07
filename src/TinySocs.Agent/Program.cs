using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Queueing;
using TinySocs.Agent.Shipper;

namespace TinySocs.Agent
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var host = Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "TinySocsAgent";
                })
                .ConfigureServices((context, services) =>
                {
                    // Config loader + strongly-typed config
                    services.AddSingleton<ConfigLoader>();
                    services.AddSingleton<AgentConfig>(sp =>
                    {
                        var loader = sp.GetRequiredService<ConfigLoader>();
                        return loader.Load();
                    });

                    // Queue writer (disk-backed JSONL queue; stubbed for now)
                    services.AddSingleton<IQueueWriter, FileQueueWriter>();

                    // Queue reader + shipper
                    services.AddSingleton<IQueueReader, FileQueueReader>();
                    services.AddSingleton<IShipper, OpenSearchBulkShipper>();

                    // Hosted service that will run the agent
                    services.AddHostedService<AgentService>();
                })
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    // later: add file logging to ProgramData
                })
                .Build();

            host.Run();
        }
    }
}