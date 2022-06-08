/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.logstash;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.anno.JRubyClass;
import org.jruby.exceptions.RaiseException;
import org.jruby.javasupport.JavaUtil;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.logstash.ackedqueue.QueueFactoryExt;
import org.logstash.ackedqueue.ext.JRubyAckedQueueExt;
import org.logstash.ackedqueue.ext.JRubyWrappedAckedQueueExt;
import org.logstash.common.AbstractDeadLetterQueueWriterExt;
import org.logstash.common.BufferedTokenizerExt;
import org.logstash.config.ir.compiler.AbstractFilterDelegatorExt;
import org.logstash.config.ir.compiler.AbstractOutputDelegatorExt;
import org.logstash.config.ir.compiler.FilterDelegatorExt;
import org.logstash.config.ir.compiler.JavaFilterDelegatorExt;
import org.logstash.config.ir.compiler.JavaInputDelegatorExt;
import org.logstash.config.ir.compiler.JavaOutputDelegatorExt;
import org.logstash.config.ir.compiler.OutputDelegatorExt;
import org.logstash.config.ir.compiler.OutputStrategyExt;
import org.logstash.execution.AbstractPipelineExt;
import org.logstash.execution.AbstractWrappedQueueExt;
import org.logstash.execution.ConvergeResultExt;
import org.logstash.execution.EventDispatcherExt;
import org.logstash.execution.ExecutionContextExt;
import org.logstash.execution.JavaBasePipelineExt;
import org.logstash.execution.PipelineReporterExt;
import org.logstash.execution.QueueReadClientBase;
import org.logstash.execution.ShutdownWatcherExt;
import org.logstash.ext.JRubyAbstractQueueWriteClientExt;
import org.logstash.ext.JRubyLogstashErrorsExt;
import org.logstash.ext.JRubyWrappedWriteClientExt;
import org.logstash.ext.JrubyAckedReadClientExt;
import org.logstash.ext.JrubyAckedWriteClientExt;
import org.logstash.ext.JrubyEventExtLibrary;
import org.logstash.ext.JrubyMemoryReadClientExt;
import org.logstash.ext.JrubyMemoryWriteClientExt;
import org.logstash.ext.JrubyTimestampExtLibrary;
import org.logstash.ext.JrubyWrappedSynchronousQueueExt;
import org.logstash.instrument.metrics.AbstractMetricExt;
import org.logstash.instrument.metrics.AbstractNamespacedMetricExt;
import org.logstash.instrument.metrics.AbstractSimpleMetricExt;
import org.logstash.instrument.metrics.MetricExt;
import org.logstash.instrument.metrics.NamespacedMetricExt;
import org.logstash.instrument.metrics.NullMetricExt;
import org.logstash.instrument.metrics.NullNamespacedMetricExt;
import org.logstash.instrument.metrics.SnapshotExt;
import org.logstash.log.DeprecationLoggerExt;
import org.logstash.log.LoggableExt;
import org.logstash.log.LoggerExt;
import org.logstash.log.PluginLoggerExt;
import org.logstash.log.SlowLoggerExt;
import org.logstash.plugins.HooksRegistryExt;
import org.logstash.plugins.UniversalPluginExt;
import org.logstash.plugins.factory.ContextualizerExt;
import org.logstash.util.UtilExt;
import org.logstash.plugins.factory.ExecutionContextFactoryExt;
import org.logstash.plugins.factory.PluginMetricsFactoryExt;
import org.logstash.plugins.factory.PluginFactoryExt;

import java.util.stream.Stream;

/**
 * Utilities around interaction with the {@link Ruby} runtime.
 */
public final class RubyUtil {

    /**
     * Reference to the global {@link Ruby} runtime.
     */
    public static final Ruby RUBY;

    public static final RubyClass RUBY_EVENT_CLASS;

    public static final RubyClass RUBY_TIMESTAMP_CLASS;

    public static final RubyClass PARSER_ERROR;

    public static final RubyClass GENERATOR_ERROR;

    public static final RubyClass LOGSTASH_ERROR;

    public static final RubyClass TIMESTAMP_PARSER_ERROR;

    public static final RubyClass WRAPPED_WRITE_CLIENT_CLASS;

    public static final RubyClass QUEUE_READ_CLIENT_BASE_CLASS;

    public static final RubyClass MEMORY_READ_CLIENT_CLASS;

    public static final RubyClass ACKED_READ_CLIENT_CLASS;

    public static final RubyClass ABSTRACT_WRITE_CLIENT_CLASS;

    public static final RubyClass MEMORY_WRITE_CLIENT_CLASS;

    public static final RubyClass ACKED_WRITE_CLIENT_CLASS;

    public static final RubyClass ABSTRACT_WRAPPED_QUEUE_CLASS;

    public static final RubyClass WRAPPED_SYNCHRONOUS_QUEUE_CLASS;

    public static final RubyClass WRAPPED_ACKED_QUEUE_CLASS;

    public static final RubyClass ACKED_QUEUE_CLASS;

    public static final RubyClass ABSTRACT_OUTPUT_DELEGATOR_CLASS;

    public static final RubyClass ABSTRACT_FILTER_DELEGATOR_CLASS;

    public static final RubyClass RUBY_OUTPUT_DELEGATOR_CLASS;

    public static final RubyClass JAVA_OUTPUT_DELEGATOR_CLASS;

    public static final RubyClass JAVA_FILTER_DELEGATOR_CLASS;

    public static final RubyClass JAVA_INPUT_DELEGATOR_CLASS;

    public static final RubyClass FILTER_DELEGATOR_CLASS;

    public static final RubyClass OUTPUT_STRATEGY_REGISTRY;

    public static final RubyClass OUTPUT_STRATEGY_ABSTRACT;

    public static final RubyClass OUTPUT_STRATEGY_SIMPLE_ABSTRACT;

    public static final RubyClass OUTPUT_STRATEGY_LEGACY;

    public static final RubyClass OUTPUT_STRATEGY_SINGLE;

    public static final RubyClass OUTPUT_STRATEGY_SHARED;

    public static final RubyClass BUFFERED_TOKENIZER;

    public static final RubyClass ABSTRACT_METRIC_CLASS;

    public static final RubyClass ABSTRACT_SIMPLE_METRIC_CLASS;

    public static final RubyClass ABSTRACT_NAMESPACED_METRIC_CLASS;

    public static final RubyClass METRIC_CLASS;

    public static final RubyClass NULL_METRIC_CLASS;

    public static final RubyClass NULL_COUNTER_CLASS;

    public static final RubyClass NAMESPACED_METRIC_CLASS;

    public static final RubyClass NULL_NAMESPACED_METRIC_CLASS;

    public static final RubyClass METRIC_EXCEPTION_CLASS;

    public static final RubyClass METRIC_NO_KEY_PROVIDED_CLASS;

    public static final RubyClass METRIC_NO_BLOCK_PROVIDED_CLASS;

    public static final RubyClass METRIC_NO_NAMESPACE_PROVIDED_CLASS;

    public static final RubyClass METRIC_SNAPSHOT_CLASS;

    public static final RubyClass TIMED_EXECUTION_CLASS;

    public static final RubyClass NULL_TIMED_EXECUTION_CLASS;

    public static final RubyClass ABSTRACT_DLQ_WRITER_CLASS;

    public static final RubyClass DUMMY_DLQ_WRITER_CLASS;

    public static final RubyClass PLUGIN_DLQ_WRITER_CLASS;

    public static final RubyClass EXECUTION_CONTEXT_CLASS;

    public static final RubyClass BUG_CLASS;

    public static final RubyClass EXECUTION_CONTEXT_FACTORY_CLASS;

    public static final RubyClass PLUGIN_METRICS_FACTORY_CLASS;

    public static final RubyClass PLUGIN_FACTORY_CLASS;

    public static final RubyModule PLUGIN_CONTEXTUALIZER_MODULE;

    public static final RubyClass LOGGER;

    public static final RubyModule LOGGABLE_MODULE;

    public static final RubyClass DEPRECATION_LOGGER;

    public static final RubyClass SLOW_LOGGER;

    public static final RubyModule UTIL_MODULE;

    public static final RubyClass CONFIGURATION_ERROR_CLASS;

    public static final RubyClass UNIVERSAL_PLUGIN_CLASS;

    public static final RubyClass EVENT_DISPATCHER_CLASS;

    public static final RubyClass PIPELINE_REPORTER_CLASS;

    public static final RubyClass SHUTDOWN_WATCHER_CLASS;

    public static final RubyClass CONVERGE_RESULT_CLASS;

    public static final RubyClass ACTION_RESULT_CLASS;

    public static final RubyClass FAILED_ACTION_CLASS;

    public static final RubyClass SUCCESSFUL_ACTION_CLASS;

    public static final RubyClass PIPELINE_REPORTER_SNAPSHOT_CLASS;

    public static final RubyClass QUEUE_FACTORY_CLASS;

    public static final RubyClass HOOKS_REGISTRY_CLASS;

    public static final RubyClass ABSTRACT_PIPELINE_CLASS;

    public static final RubyClass JAVA_PIPELINE_CLASS;

    /**
     * Logstash Ruby Module.
     */
    private static final RubyModule LOGSTASH_MODULE;

    private static final RubyModule OUTPUT_DELEGATOR_STRATEGIES;

    private static final RubyModule PLUGINS_MODULE;

    static {
        RUBY = Ruby.getGlobalRuntime();
        LOGSTASH_MODULE = RUBY.getOrCreateModule("LogStash");
        Stream.of(
            "Inputs", "Outputs", "Filters", "Search", "Config", "File", "Web", "PluginMixins",
            "PluginManager", "Api", "Modules"
        ).forEach(module -> RUBY.defineModuleUnder(module, LOGSTASH_MODULE));
        PLUGINS_MODULE = RUBY.defineModuleUnder("Plugins", LOGSTASH_MODULE);
        final RubyModule instrumentModule =
            RUBY.defineModuleUnder("Instrument", LOGSTASH_MODULE);
        METRIC_SNAPSHOT_CLASS =
            instrumentModule.defineClassUnder("Snapshot", RUBY.getObject(), SnapshotExt::new);
        METRIC_SNAPSHOT_CLASS.defineAnnotatedMethods(SnapshotExt.class);
        EXECUTION_CONTEXT_FACTORY_CLASS = PLUGINS_MODULE.defineClassUnder(
            "ExecutionContextFactory", RUBY.getObject(),
            ExecutionContextFactoryExt::new
        );
        PLUGIN_METRICS_FACTORY_CLASS = PLUGINS_MODULE.defineClassUnder(
            "PluginMetricsFactory", RUBY.getObject(), PluginMetricsFactoryExt::new
        );
        SHUTDOWN_WATCHER_CLASS =
            setupLogstashClass(ShutdownWatcherExt::new, ShutdownWatcherExt.class);
        PLUGIN_METRICS_FACTORY_CLASS.defineAnnotatedMethods(PluginMetricsFactoryExt.class);
        EXECUTION_CONTEXT_FACTORY_CLASS.defineAnnotatedMethods(
            ExecutionContextFactoryExt.class
        );
        METRIC_EXCEPTION_CLASS = instrumentModule.defineClassUnder(
            "MetricException", RUBY.getException(), MetricExt.MetricException::new
        );
        METRIC_NO_KEY_PROVIDED_CLASS = instrumentModule.defineClassUnder(
            "MetricNoKeyProvided", METRIC_EXCEPTION_CLASS, MetricExt.MetricNoKeyProvided::new
        );
        METRIC_NO_BLOCK_PROVIDED_CLASS = instrumentModule.defineClassUnder(
            "MetricNoBlockProvided", METRIC_EXCEPTION_CLASS,
            MetricExt.MetricNoBlockProvided::new
        );
        METRIC_NO_NAMESPACE_PROVIDED_CLASS = instrumentModule.defineClassUnder(
            "MetricNoNamespaceProvided", METRIC_EXCEPTION_CLASS,
            MetricExt.MetricNoNamespaceProvided::new
        );
        ABSTRACT_METRIC_CLASS = instrumentModule.defineClassUnder(
            "AbstractMetric", RUBY.getObject(),
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_NAMESPACED_METRIC_CLASS = instrumentModule.defineClassUnder(
            "AbstractNamespacedMetric", ABSTRACT_METRIC_CLASS,
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_SIMPLE_METRIC_CLASS = instrumentModule.defineClassUnder(
            "AbstractSimpleMetric", ABSTRACT_METRIC_CLASS,
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        METRIC_CLASS = instrumentModule.defineClassUnder(
            "Metric", ABSTRACT_SIMPLE_METRIC_CLASS, MetricExt::new
        );
        NULL_METRIC_CLASS = instrumentModule.defineClassUnder(
            "NullMetric", ABSTRACT_SIMPLE_METRIC_CLASS, NullMetricExt::new
        );
        TIMED_EXECUTION_CLASS = METRIC_CLASS.defineClassUnder(
            "TimedExecution", RUBY.getObject(), MetricExt.TimedExecution::new
        );
        NULL_TIMED_EXECUTION_CLASS = NULL_METRIC_CLASS.defineClassUnder(
            "NullTimedExecution", RUBY.getObject(), NullMetricExt.NullTimedExecution::new
        );
        NULL_COUNTER_CLASS = METRIC_CLASS.defineClassUnder(
            "NullCounter", RUBY.getObject(), NullNamespacedMetricExt.NullCounter::new
        );
        NAMESPACED_METRIC_CLASS = instrumentModule.defineClassUnder(
            "NamespacedMetric", ABSTRACT_NAMESPACED_METRIC_CLASS, NamespacedMetricExt::new
        );
        NULL_NAMESPACED_METRIC_CLASS = instrumentModule.defineClassUnder(
            "NamespacedNullMetric", ABSTRACT_NAMESPACED_METRIC_CLASS,
            NullNamespacedMetricExt::new
        );
        ABSTRACT_METRIC_CLASS.defineAnnotatedMethods(AbstractMetricExt.class);
        ABSTRACT_SIMPLE_METRIC_CLASS.defineAnnotatedMethods(AbstractSimpleMetricExt.class);
        ABSTRACT_NAMESPACED_METRIC_CLASS.defineAnnotatedMethods(AbstractNamespacedMetricExt.class);
        METRIC_CLASS.defineAnnotatedMethods(MetricExt.class);
        NULL_METRIC_CLASS.defineAnnotatedMethods(NullMetricExt.class);
        NAMESPACED_METRIC_CLASS.defineAnnotatedMethods(NamespacedMetricExt.class);
        NULL_NAMESPACED_METRIC_CLASS.defineAnnotatedMethods(NullNamespacedMetricExt.class);
        TIMED_EXECUTION_CLASS.defineAnnotatedMethods(MetricExt.TimedExecution.class);
        NULL_TIMED_EXECUTION_CLASS.defineAnnotatedMethods(NullMetricExt.NullTimedExecution.class);
        NULL_COUNTER_CLASS.defineAnnotatedMethods(NullNamespacedMetricExt.NullCounter.class);
        UTIL_MODULE = LOGSTASH_MODULE.defineModuleUnder("Util");
        UTIL_MODULE.defineAnnotatedMethods(UtilExt.class);
        ABSTRACT_DLQ_WRITER_CLASS = UTIL_MODULE.defineClassUnder(
            "AbstractDeadLetterQueueWriter", RUBY.getObject(),
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_DLQ_WRITER_CLASS.defineAnnotatedMethods(AbstractDeadLetterQueueWriterExt.class);
        DUMMY_DLQ_WRITER_CLASS = UTIL_MODULE.defineClassUnder(
            "DummyDeadLetterQueueWriter", ABSTRACT_DLQ_WRITER_CLASS,
            AbstractDeadLetterQueueWriterExt.DummyDeadLetterQueueWriterExt::new
        );
        DUMMY_DLQ_WRITER_CLASS.defineAnnotatedMethods(
            AbstractDeadLetterQueueWriterExt.DummyDeadLetterQueueWriterExt.class
        );
        PLUGIN_DLQ_WRITER_CLASS = UTIL_MODULE.defineClassUnder(
            "PluginDeadLetterQueueWriter", ABSTRACT_DLQ_WRITER_CLASS,
            AbstractDeadLetterQueueWriterExt.PluginDeadLetterQueueWriterExt::new
        );
        PLUGIN_DLQ_WRITER_CLASS.defineAnnotatedMethods(
            AbstractDeadLetterQueueWriterExt.PluginDeadLetterQueueWriterExt.class
        );
        OUTPUT_STRATEGY_REGISTRY = setupLogstashClass(
            OutputStrategyExt.OutputStrategyRegistryExt::new,
            OutputStrategyExt.OutputStrategyRegistryExt.class
        );
        BUFFERED_TOKENIZER = RUBY.getOrCreateModule("FileWatch").defineClassUnder(
            "BufferedTokenizer", RUBY.getObject(), BufferedTokenizerExt::new
        );
        BUFFERED_TOKENIZER.defineAnnotatedMethods(BufferedTokenizerExt.class);
        OUTPUT_DELEGATOR_STRATEGIES =
            RUBY.defineModuleUnder("OutputDelegatorStrategies", LOGSTASH_MODULE);
        OUTPUT_STRATEGY_ABSTRACT = OUTPUT_DELEGATOR_STRATEGIES.defineClassUnder(
            "AbstractStrategy", RUBY.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        OUTPUT_STRATEGY_SIMPLE_ABSTRACT = OUTPUT_DELEGATOR_STRATEGIES.defineClassUnder(
            "SimpleAbstractStrategy", OUTPUT_STRATEGY_ABSTRACT,
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        OUTPUT_STRATEGY_LEGACY = OUTPUT_DELEGATOR_STRATEGIES.defineClassUnder(
            "Legacy", OUTPUT_STRATEGY_ABSTRACT,
            OutputStrategyExt.LegacyOutputStrategyExt::new
        );
        OUTPUT_STRATEGY_SINGLE = OUTPUT_DELEGATOR_STRATEGIES.defineClassUnder(
            "Single", OUTPUT_STRATEGY_SIMPLE_ABSTRACT,
            OutputStrategyExt.SingleOutputStrategyExt::new
        );
        OUTPUT_STRATEGY_SHARED = OUTPUT_DELEGATOR_STRATEGIES.defineClassUnder(
            "Shared", OUTPUT_STRATEGY_SIMPLE_ABSTRACT,
            OutputStrategyExt.SharedOutputStrategyExt::new
        );
        OUTPUT_STRATEGY_ABSTRACT.defineAnnotatedMethods(OutputStrategyExt.AbstractOutputStrategyExt.class);
        OUTPUT_STRATEGY_ABSTRACT.defineAnnotatedMethods(OutputStrategyExt.SimpleAbstractOutputStrategyExt.class);
        OUTPUT_STRATEGY_SHARED.defineAnnotatedMethods(OutputStrategyExt.SharedOutputStrategyExt.class);
        OUTPUT_STRATEGY_SINGLE.defineAnnotatedMethods(OutputStrategyExt.SingleOutputStrategyExt.class);
        OUTPUT_STRATEGY_LEGACY.defineAnnotatedMethods(OutputStrategyExt.LegacyOutputStrategyExt.class);
        final OutputStrategyExt.OutputStrategyRegistryExt outputStrategyRegistry =
            OutputStrategyExt.OutputStrategyRegistryExt.instance(
                RUBY.getCurrentContext(), OUTPUT_DELEGATOR_STRATEGIES
            );
        outputStrategyRegistry.register(
            RUBY.getCurrentContext(), RUBY.newSymbol("shared"), OUTPUT_STRATEGY_SHARED
        );
        outputStrategyRegistry.register(
            RUBY.getCurrentContext(), RUBY.newSymbol("legacy"), OUTPUT_STRATEGY_LEGACY
        );
        outputStrategyRegistry.register(
            RUBY.getCurrentContext(), RUBY.newSymbol("single"), OUTPUT_STRATEGY_SINGLE
        );
        EXECUTION_CONTEXT_CLASS = setupLogstashClass(
            ExecutionContextExt::new, ExecutionContextExt.class
        );
        EXECUTION_CONTEXT_CLASS.defineConstant("Empty", EXECUTION_CONTEXT_CLASS.newInstance(RUBY.getCurrentContext(), RUBY.getNil(), RUBY.getNil(), RUBY.getNil(), Block.NULL_BLOCK));
        RUBY_TIMESTAMP_CLASS = setupLogstashClass(
            JrubyTimestampExtLibrary.RubyTimestamp::new, JrubyTimestampExtLibrary.RubyTimestamp.class
        );
        ABSTRACT_WRAPPED_QUEUE_CLASS = LOGSTASH_MODULE.defineClassUnder(
            "AbstractWrappedQueue", RUBY.getObject(),
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_WRAPPED_QUEUE_CLASS.defineAnnotatedMethods(AbstractWrappedQueueExt.class);
        ABSTRACT_WRITE_CLIENT_CLASS = LOGSTASH_MODULE.defineClassUnder(
            "AbstractQueueWriteClient", RUBY.getObject(),
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_WRITE_CLIENT_CLASS.defineAnnotatedMethods(JRubyAbstractQueueWriteClientExt.class);
        WRAPPED_WRITE_CLIENT_CLASS =
            setupLogstashClass(JRubyWrappedWriteClientExt::new, JRubyWrappedWriteClientExt.class);
        QUEUE_READ_CLIENT_BASE_CLASS =
            setupLogstashClass(ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR, QueueReadClientBase.class);
        MEMORY_READ_CLIENT_CLASS =
            setupLogstashClass(QUEUE_READ_CLIENT_BASE_CLASS, JrubyMemoryReadClientExt::new, JrubyMemoryReadClientExt.class);
        ACKED_READ_CLIENT_CLASS =
            setupLogstashClass(QUEUE_READ_CLIENT_BASE_CLASS, JrubyAckedReadClientExt::new, JrubyAckedReadClientExt.class);
        MEMORY_WRITE_CLIENT_CLASS = setupLogstashClass(
            ABSTRACT_WRITE_CLIENT_CLASS, JrubyMemoryWriteClientExt::new,
            JrubyMemoryWriteClientExt.class
        );
        ACKED_WRITE_CLIENT_CLASS = setupLogstashClass(
            ABSTRACT_WRITE_CLIENT_CLASS, JrubyAckedWriteClientExt::new,
            JrubyAckedWriteClientExt.class
        );
        WRAPPED_SYNCHRONOUS_QUEUE_CLASS = setupLogstashClass(
            ABSTRACT_WRAPPED_QUEUE_CLASS, JrubyWrappedSynchronousQueueExt::new,
            JrubyWrappedSynchronousQueueExt.class
        );
        WRAPPED_ACKED_QUEUE_CLASS = setupLogstashClass(
            ABSTRACT_WRAPPED_QUEUE_CLASS, JRubyWrappedAckedQueueExt::new,
            JRubyWrappedAckedQueueExt.class
        );
        ACKED_QUEUE_CLASS = setupLogstashClass(JRubyAckedQueueExt::new, JRubyAckedQueueExt.class);
        QUEUE_FACTORY_CLASS = setupLogstashClass(QueueFactoryExt::new, QueueFactoryExt.class);
        RUBY_EVENT_CLASS = setupLogstashClass(
            JrubyEventExtLibrary.RubyEvent::new, JrubyEventExtLibrary.RubyEvent.class
        );
        ABSTRACT_OUTPUT_DELEGATOR_CLASS = LOGSTASH_MODULE.defineClassUnder(
            "AbstractOutputDelegator", RUBY.getObject(),
            ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_OUTPUT_DELEGATOR_CLASS.defineAnnotatedMethods(AbstractOutputDelegatorExt.class);
        RUBY_OUTPUT_DELEGATOR_CLASS = setupLogstashClass(
            ABSTRACT_OUTPUT_DELEGATOR_CLASS, OutputDelegatorExt::new, OutputDelegatorExt.class
        );
        JAVA_OUTPUT_DELEGATOR_CLASS = setupLogstashClass(
            ABSTRACT_OUTPUT_DELEGATOR_CLASS, JavaOutputDelegatorExt::new,
            JavaOutputDelegatorExt.class
        );
        ABSTRACT_FILTER_DELEGATOR_CLASS = LOGSTASH_MODULE.defineClassUnder(
                "AbstractFilterDelegator", RUBY.getObject(),
                ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ABSTRACT_FILTER_DELEGATOR_CLASS.defineAnnotatedMethods(AbstractFilterDelegatorExt.class);
        JAVA_FILTER_DELEGATOR_CLASS = setupLogstashClass(
                ABSTRACT_FILTER_DELEGATOR_CLASS, JavaFilterDelegatorExt::new,
                JavaFilterDelegatorExt.class
        );
        FILTER_DELEGATOR_CLASS = setupLogstashClass(
                ABSTRACT_FILTER_DELEGATOR_CLASS, FilterDelegatorExt::new,
                FilterDelegatorExt.class
        );
        JAVA_INPUT_DELEGATOR_CLASS = setupLogstashClass(JavaInputDelegatorExt::new, JavaInputDelegatorExt.class);
        final RubyModule loggingModule = LOGSTASH_MODULE.defineOrGetModuleUnder("Logging");
        LOGGER = loggingModule.defineClassUnder("Logger", RUBY.getObject(), LoggerExt::new);
        LOGGER.defineAnnotatedMethods(LoggerExt.class);
        final RubyClass pluginLoggerClass = loggingModule.defineClassUnder("PluginLogger", LOGGER, PluginLoggerExt::new);
        pluginLoggerClass.defineAnnotatedMethods(PluginLoggerExt.class);
        SLOW_LOGGER = loggingModule.defineClassUnder(
            "SlowLogger", RUBY.getObject(), SlowLoggerExt::new);
        SLOW_LOGGER.defineAnnotatedMethods(SlowLoggerExt.class);
        DEPRECATION_LOGGER = loggingModule.defineClassUnder(
            "DeprecationLogger", RUBY.getObject(), DeprecationLoggerExt::new);
        DEPRECATION_LOGGER.defineAnnotatedMethods(DeprecationLoggerExt.class);

        LOGGABLE_MODULE = UTIL_MODULE.defineModuleUnder("Loggable");
        LOGGABLE_MODULE.defineAnnotatedMethods(LoggableExt.class);
        ABSTRACT_PIPELINE_CLASS =
            setupLogstashClass(AbstractPipelineExt::new, AbstractPipelineExt.class);
        JAVA_PIPELINE_CLASS = setupLogstashClass(
            ABSTRACT_PIPELINE_CLASS, JavaBasePipelineExt::new, JavaBasePipelineExt.class
        );
        final RubyModule json = LOGSTASH_MODULE.defineOrGetModuleUnder("Json");
        final RubyClass stdErr = RUBY.getStandardError();
        LOGSTASH_ERROR = LOGSTASH_MODULE.defineClassUnder(
            "Error", stdErr, JRubyLogstashErrorsExt.LogstashRubyError::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "EnvironmentError", stdErr, JRubyLogstashErrorsExt.LogstashEnvironmentError::new
        );
        CONFIGURATION_ERROR_CLASS = LOGSTASH_MODULE.defineClassUnder(
            "ConfigurationError", stdErr, JRubyLogstashErrorsExt.ConfigurationError::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "PluginLoadingError", stdErr, JRubyLogstashErrorsExt.PluginLoadingError::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "ShutdownSignal", stdErr, JRubyLogstashErrorsExt.ShutdownSignal::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "PluginNoVersionError", stdErr, JRubyLogstashErrorsExt.PluginNoVersionError::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "BootstrapCheckError", stdErr, JRubyLogstashErrorsExt.BootstrapCheckError::new
        );
        BUG_CLASS = LOGSTASH_MODULE.defineClassUnder(
            "Bug", stdErr, JRubyLogstashErrorsExt.Bug::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "ThisMethodWasRemoved", BUG_CLASS,
            JRubyLogstashErrorsExt.ThisMethodWasRemoved::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "ConfigLoadingError", stdErr, JRubyLogstashErrorsExt.ConfigLoadingError::new
        );
        LOGSTASH_MODULE.defineClassUnder(
            "InvalidSourceLoaderSettingError", stdErr,
            JRubyLogstashErrorsExt.InvalidSourceLoaderSettingError::new
        );
        PARSER_ERROR = json.defineClassUnder(
            "ParserError", LOGSTASH_ERROR, JRubyLogstashErrorsExt.LogstashRubyParserError::new
        );
        TIMESTAMP_PARSER_ERROR = LOGSTASH_MODULE.defineClassUnder(
            "TimestampParserError", stdErr, JRubyLogstashErrorsExt.LogstashTimestampParserError::new
        );
        GENERATOR_ERROR = json.defineClassUnder("GeneratorError", LOGSTASH_ERROR,
            JRubyLogstashErrorsExt.LogstashRubyGeneratorError::new
        );
        RUBY_EVENT_CLASS.setConstant("METADATA", RUBY.newString(Event.METADATA));
        RUBY_EVENT_CLASS.setConstant(
            "METADATA_BRACKETS", RUBY.newString(Event.METADATA_BRACKETS)
        );
        RUBY_EVENT_CLASS.setConstant("TIMESTAMP", RUBY.newString(Event.TIMESTAMP));
        RUBY_EVENT_CLASS.setConstant(
            "TIMESTAMP_FAILURE_TAG", RUBY.newString(Event.TIMESTAMP_FAILURE_TAG)
        );
        RUBY_EVENT_CLASS.setConstant(
            "TIMESTAMP_FAILURE_FIELD", RUBY.newString(Event.TIMESTAMP_FAILURE_FIELD)
        );
        RUBY_EVENT_CLASS.setConstant("VERSION", RUBY.newString(Event.VERSION));
        RUBY_EVENT_CLASS.setConstant("VERSION_ONE", RUBY.newString(Event.VERSION_ONE));
        RUBY_EVENT_CLASS.defineAnnotatedMethods(JrubyEventExtLibrary.RubyEvent.class);
        RUBY_EVENT_CLASS.defineAnnotatedConstants(JrubyEventExtLibrary.RubyEvent.class);
        PLUGIN_FACTORY_CLASS = PLUGINS_MODULE.defineClassUnder(
            "PluginFactory", RUBY.getObject(), PluginFactoryExt::new
        );
        PLUGIN_FACTORY_CLASS.defineAnnotatedMethods(PluginFactoryExt.class);
        PLUGIN_CONTEXTUALIZER_MODULE = PLUGINS_MODULE.defineOrGetModuleUnder("Contextualizer");
        PLUGIN_CONTEXTUALIZER_MODULE.defineAnnotatedMethods(ContextualizerExt.class);
        UNIVERSAL_PLUGIN_CLASS =
            setupLogstashClass(UniversalPluginExt::new, UniversalPluginExt.class);
        EVENT_DISPATCHER_CLASS =
            setupLogstashClass(EventDispatcherExt::new, EventDispatcherExt.class);
        PIPELINE_REPORTER_CLASS =
            setupLogstashClass(PipelineReporterExt::new, PipelineReporterExt.class);
        PIPELINE_REPORTER_CLASS.defineAnnotatedMethods(PipelineReporterExt.class);
        PIPELINE_REPORTER_SNAPSHOT_CLASS = PIPELINE_REPORTER_CLASS.defineClassUnder(
            "Snapshot", RUBY.getObject(), PipelineReporterExt.SnapshotExt::new
        );
        PIPELINE_REPORTER_SNAPSHOT_CLASS.defineAnnotatedMethods(
            PipelineReporterExt.SnapshotExt.class
        );
        CONVERGE_RESULT_CLASS = setupLogstashClass(ConvergeResultExt::new, ConvergeResultExt.class);
        ACTION_RESULT_CLASS = CONVERGE_RESULT_CLASS.defineClassUnder(
            "ActionResult", RUBY.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR
        );
        ACTION_RESULT_CLASS.defineAnnotatedMethods(ConvergeResultExt.ActionResultExt.class);
        SUCCESSFUL_ACTION_CLASS = CONVERGE_RESULT_CLASS.defineClassUnder(
            "SuccessfulAction", ACTION_RESULT_CLASS, ConvergeResultExt.SuccessfulActionExt::new
        );
        SUCCESSFUL_ACTION_CLASS.defineAnnotatedMethods(ConvergeResultExt.SuccessfulActionExt.class);
        FAILED_ACTION_CLASS = CONVERGE_RESULT_CLASS.defineClassUnder(
            "FailedAction", ACTION_RESULT_CLASS, ConvergeResultExt.FailedActionExt::new
        );
        FAILED_ACTION_CLASS.defineAnnotatedMethods(ConvergeResultExt.FailedActionExt.class);
        HOOKS_REGISTRY_CLASS =
            PLUGINS_MODULE.defineClassUnder("HooksRegistry", RUBY.getObject(), HooksRegistryExt::new);
        HOOKS_REGISTRY_CLASS.defineAnnotatedMethods(HooksRegistryExt.class);
        RUBY.getGlobalVariables().set("$LS_JARS_LOADED", RUBY.newString("true"));
        RubyJavaIntegration.setupRubyJavaIntegration(RUBY);
    }

    private RubyUtil() {
    }

    /**
     * Wraps a Java exception in a JRuby IOError NativeException.
     * This preserves the Java stacktrace and bubble up as a Ruby IOError
     * @param runtime the Ruby runtime context
     * @param e the Java exception to wrap
     * @return RaiseException the wrapped IOError
     */
    @SuppressWarnings("deprecation")
    public static RaiseException newRubyIOError(Ruby runtime, Throwable e) {
        // will preserve Java stacktrace & bubble up as a Ruby IOError
        return new RaiseException(e, new org.jruby.NativeException(runtime, runtime.getIOError(), e));
    }

    /**
     * Sets up a Java-defined {@link RubyClass} in the Logstash Ruby module.
     * @param allocator Allocator of the class
     * @param jclass Underlying Java class that is annotated by {@link JRubyClass}
     * @return RubyClass
     */
    private static RubyClass setupLogstashClass(final ObjectAllocator allocator,
        final Class<?> jclass) {
        return setupLogstashClass(RUBY.getObject(), allocator, jclass);
    }

    /**
     * Sets up a Java-defined {@link RubyClass} in the Logstash Ruby module.
     * @param parent Parent RubyClass
     * @param allocator Allocator of the class
     * @param jclass Underlying Java class that is annotated by {@link JRubyClass}
     * @return RubyClass
     */
    private static RubyClass setupLogstashClass(final RubyClass parent,
        final ObjectAllocator allocator, final Class<?> jclass) {
        final RubyClass clazz = RUBY.defineClassUnder(
            jclass.getAnnotation(JRubyClass.class).name()[0], parent, allocator, LOGSTASH_MODULE
        );
        clazz.defineAnnotatedMethods(jclass);
        return clazz;
    }

    /**
     * Convert a Java object to a Ruby representative.
     * @param javaObject the object to convert (might be null)
     * @return a Ruby wrapper
     */
    public static IRubyObject toRubyObject(Object javaObject) {
        return JavaUtil.convertJavaToRuby(RUBY, javaObject);
    }

    /**
     * Cast an IRubyObject that may be nil to a specific class
     * @param objectOrNil an object of either type {@code <T>} or nil.
     * @param <T> the type to cast non-nil values to
     * @return The given value, cast to {@code <T>}, or null.
     */
    public static <T extends IRubyObject> T nilSafeCast(final IRubyObject objectOrNil) {
        if (objectOrNil == null || objectOrNil.isNil()) { return null; }

        @SuppressWarnings("unchecked")
        final T objectAsCasted = (T) objectOrNil;

        return objectAsCasted;
    }
}
