using System.Threading;
using System.Threading.Tasks;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Queueing
{
    /// <summary>
    /// Abstraction for appending events to the durable on-disk queue.
    /// </summary>
    public interface IQueueWriter
    {
        /// <summary>
        /// Append a single event to the queue. Implementations are responsible
        /// for serialization, segment rotation, and flushing behaviour.
        /// </summary>
        Task EnqueueAsync(AgentEvent evt, CancellationToken cancellationToken);
    }
}