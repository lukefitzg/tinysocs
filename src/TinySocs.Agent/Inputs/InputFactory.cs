using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Queueing;

namespace TinySocs.Agent.Inputs
{
    /// <summary>
    /// Factory for constructing input instances (eventlog, fake, etc.) from configuration.
    /// </summary>
    public static class InputFactory
    {
        public static IReadOnlyList<IInput> CreateInputs(
            AgentConfig config,
            IQueueWriter queueWriter,
            ILoggerFactory loggerFactory)
        {
            var results = new List<IInput>();

            if (config.Inputs == null || config.Inputs.Count == 0)
            {
                return results;
            }

            var factoryLogger = loggerFactory.CreateLogger(typeof(InputFactory));

            foreach (var inputConfig in config.Inputs)
            {
                if (string.Equals(inputConfig.Type, "eventlog", StringComparison.OrdinalIgnoreCase))
                {
                    var logger = loggerFactory.CreateLogger<EventLogInput>();
                    var input = new EventLogInput(logger, config, queueWriter);
                    results.Add(input);
                }
                else if (string.Equals(inputConfig.Type, "fake", StringComparison.OrdinalIgnoreCase))
                {
                    var logger = loggerFactory.CreateLogger<FakeInput>();
                    var input = new FakeInput(logger, config, queueWriter);
                    results.Add(input);
                }
                else
                {
                    factoryLogger.LogWarning(
                        "Unsupported input type '{Type}' in configuration. Skipping.",
                        inputConfig.Type);
                }
            }

            return results;
        }
    }
}