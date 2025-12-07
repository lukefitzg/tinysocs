using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// Reads events from the on-disk queue in order.
    /// Implementations produce batches of AgentEvent instances.
    /// </summary>
    public interface IQueueReader
    {
        /// <summary>
        /// Fetch the next batch of events, or return an empty list if none are available.
        /// Must not block indefinitely.
        /// </summary>
        Task<IReadOnlyList<AgentEvent>> ReadBatchAsync(
            int maxEvents,
            int maxBytes,
            CancellationToken cancellationToken);

        /// <summary>
        /// After successful shipping, mark the read events as acknowledged
        /// (allowing segment deletion or advancement).
        /// </summary>
        Task AcknowledgeAsync(int count, CancellationToken cancellationToken);
    }
}