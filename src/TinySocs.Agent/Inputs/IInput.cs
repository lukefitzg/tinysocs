using System.Threading;
using System.Threading.Tasks;

namespace TinySocs.Agent.Inputs;

/// <summary>
/// Abstraction for a logical input (eventlog, file, etc).
/// </summary>
public interface IInput
{
    /// <summary>
    /// Start consuming from this input and forwarding events to the queue.
    /// Returns when the input is finished or stoppingToken is cancelled.
    /// </summary>
    Task RunAsync(CancellationToken stoppingToken);
}