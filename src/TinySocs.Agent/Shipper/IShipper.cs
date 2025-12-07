using System.Threading;
using System.Threading.Tasks;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// Abstraction for a component that reads from the queue
    /// and ships events to a downstream system (e.g. OpenSearch).
    /// </summary>
    public interface IShipper
    {
        /// <summary>
        /// Run the shipper until the token is cancelled.
        /// Implementations should handle their own retry/backoff logic.
        /// </summary>
        Task RunAsync(CancellationToken stoppingToken);
    }
}