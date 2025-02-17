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


package org.logstash.config.ir.compiler;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.stream.Collectors;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.internal.runtime.methods.DynamicMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.logstash.RubyUtil;
import org.logstash.execution.ExecutionContextExt;
import org.logstash.plugins.factory.ContextualizerExt;

import static org.logstash.RubyUtil.PLUGIN_CONTEXTUALIZER_MODULE;

public final class OutputStrategyExt {

    private OutputStrategyExt() {
        // Just a holder for the nested classes
    }

    @JRubyClass(name = "OutputDelegatorStrategyRegistry")
    public static final class OutputStrategyRegistryExt extends RubyObject {

        private static final long serialVersionUID = 1L;

        private static OutputStrategyExt.OutputStrategyRegistryExt instance;

        private RubyHash map;

        public OutputStrategyRegistryExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @JRubyMethod(meta = true)
        public static synchronized OutputStrategyExt.OutputStrategyRegistryExt instance(
            final ThreadContext context, final IRubyObject recv) {
            if (instance == null) {
                instance = new OutputStrategyExt.OutputStrategyRegistryExt(
                    context.runtime, RubyUtil.OUTPUT_STRATEGY_REGISTRY
                );
                instance.init(context);
            }
            return instance;
        }

        @JRubyMethod(name = "initialize")
        public IRubyObject init(final ThreadContext context) {
            map = RubyHash.newHash(context.runtime);
            return this;
        }

        @JRubyMethod
        public IRubyObject classes(final ThreadContext context) {
            return map.values(context);
        }

        @JRubyMethod
        public IRubyObject types() {
            return map.keys();
        }

        @JRubyMethod
        public IRubyObject register(final ThreadContext context, final IRubyObject type,
            final IRubyObject klass) {
            return map.op_aset(context, type, klass);
        }

        @JRubyMethod(name = "class_for")
        @SuppressWarnings("unchecked")
        public RubyClass classFor(final ThreadContext context, final IRubyObject type) {
            final IRubyObject klass = map.op_aref(context, type);
            if (!klass.isTrue()) {
                throw new IllegalArgumentException(
                    String.format(
                        "Could not find output delegator strategy of type '%s'. Value strategies: %s",
                        type.asJavaString(),
                        map.values(context).stream().map(v -> ((IRubyObject) v).asJavaString())
                            .collect(Collectors.joining(", "))
                    )
                );
            }
            return (RubyClass) klass;
        }
    }

    @JRubyClass(name = "AbstractStrategy")
    public abstract static class AbstractOutputStrategyExt extends RubyObject {

        private static final long serialVersionUID = 1L;

        private transient DynamicMethod outputMethod;

        private RubyClass outputClass;

        public AbstractOutputStrategyExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @JRubyMethod
        @SuppressWarnings("unchecked")
        public final IRubyObject register(final ThreadContext context) {
            return reg(context);
        }

        @JRubyMethod(name = "do_close")
        @SuppressWarnings("unchecked")
        public final IRubyObject doClose(final ThreadContext context) {
            return close(context);
        }

        @JRubyMethod(name = AbstractOutputDelegatorExt.OUTPUT_METHOD_NAME)
        public final IRubyObject multiReceive(final ThreadContext context, final IRubyObject events)
            throws InterruptedException {
            return output(context, events);
        }

        protected final void initOutputCallsite(final RubyClass outputClass) {
            outputMethod = outputClass.searchMethod(AbstractOutputDelegatorExt.OUTPUT_METHOD_NAME);
            this.outputClass = outputClass;
        }

        protected final void invokeOutput(final ThreadContext context, final IRubyObject batch,
            final IRubyObject pluginInstance) {
            outputMethod.call(
                context, pluginInstance, outputClass, AbstractOutputDelegatorExt.OUTPUT_METHOD_NAME,
                batch
            );
        }

        protected abstract IRubyObject output(ThreadContext context, IRubyObject events)
            throws InterruptedException;

        protected abstract IRubyObject close(ThreadContext context);

        protected abstract IRubyObject reg(ThreadContext context);
    }

    @JRubyClass(name = "Legacy", parent = "AbstractStrategy")
    public static final class LegacyOutputStrategyExt extends OutputStrategyExt.AbstractOutputStrategyExt {

        private static final long serialVersionUID = 1L;

        private transient BlockingQueue<IRubyObject> workerQueue;

        private transient IRubyObject workerCount;

        private @SuppressWarnings({"rawtypes"}) RubyArray workers;

        public LegacyOutputStrategyExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @JRubyMethod(required = 4)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final RubyClass outputClass = (RubyClass) args[0];
            final IRubyObject metric = args[1];
            final ExecutionContextExt executionContext = (ExecutionContextExt) args[2];
            final RubyHash pluginArgs = (RubyHash) args[3];
            IRubyObject pipeline = executionContext.callMethod(context, "pipeline");
            IRubyObject settings = pipeline.callMethod(context, "settings");
            workerCount = settings.callMethod(context, "get_value", context.runtime.newString("pipeline.workers"));
            if (workerCount.isNil()) {
                workerCount = RubyFixnum.one(context.runtime);
            }
            final int count = workerCount.convertToInteger().getIntValue();
            workerQueue = new ArrayBlockingQueue<>(count);
            workers = context.runtime.newArray(count);
            for (int i = 0; i < count; ++i) {
                final IRubyObject output = ContextualizerExt.initializePlugin(context, executionContext, outputClass, pluginArgs);
                initOutputCallsite(outputClass);
                output.callMethod(context, "metric=", metric);
                workers.append(output);
                workerQueue.add(output);
            }
            return this;
        }

        @JRubyMethod(name = "worker_count")
        public IRubyObject workerCount() {
            return workerCount;
        }

        @JRubyMethod
        public IRubyObject workers() {
            return workers;
        }

        @Override
        protected IRubyObject output(final ThreadContext context, final IRubyObject events) throws InterruptedException {
            final IRubyObject worker = workerQueue.take();
            try {
                invokeOutput(context, events, worker);
                return context.nil;
            } finally {
                workerQueue.put(worker);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        protected IRubyObject close(final ThreadContext context) {
            workers.forEach(worker -> ((IRubyObject) worker).callMethod(context, "do_close"));
            return this;
        }

        @Override
        @SuppressWarnings("unchecked")
        protected IRubyObject reg(final ThreadContext context) {
            workers.forEach(worker -> ((IRubyObject) worker).callMethod(context, "register"));
            return this;
        }
    }

    @JRubyClass(name = "SimpleAbstractStrategy", parent = "AbstractStrategy")
    public abstract static class SimpleAbstractOutputStrategyExt
        extends OutputStrategyExt.AbstractOutputStrategyExt {

        private static final long serialVersionUID = 1L;

        private transient IRubyObject output;

        protected SimpleAbstractOutputStrategyExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @JRubyMethod(required = 4)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final RubyClass outputClass = (RubyClass) args[0];
            final IRubyObject metric = args[1];
            final ExecutionContextExt executionContext = (ExecutionContextExt) args[2];
            final RubyHash pluginArgs = (RubyHash) args[3];
            // TODO: fixup mocks
            // Calling "new" here manually to allow mocking the ctor in RSpec Tests
            output = ContextualizerExt.initializePlugin(context, executionContext, outputClass, pluginArgs);

            initOutputCallsite(outputClass);
            output.callMethod(context, "metric=", metric);
            return this;
        }

        @Override
        protected final IRubyObject close(final ThreadContext context) {
            return output.callMethod(context, "do_close");
        }

        @Override
        protected final IRubyObject reg(final ThreadContext context) {
            return output.callMethod(context, "register");
        }

        protected final IRubyObject doOutput(final ThreadContext context, final IRubyObject events) {
            invokeOutput(context, events, output);
            return context.nil;
        }
    }

    @JRubyClass(name = "Single", parent = "SimpleAbstractStrategy")
    public static final class SingleOutputStrategyExt extends SimpleAbstractOutputStrategyExt {

        private static final long serialVersionUID = 1L;

        public SingleOutputStrategyExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @Override
        protected IRubyObject output(final ThreadContext context, final IRubyObject events) {
            synchronized (this) {
                return doOutput(context, events);
            }
        }
    }

    @JRubyClass(name = "Shared", parent = "SimpleAbstractStrategy")
    public static final class SharedOutputStrategyExt extends SimpleAbstractOutputStrategyExt {

        private static final long serialVersionUID = 1L;

        public SharedOutputStrategyExt(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }

        @Override
        protected IRubyObject output(final ThreadContext context, final IRubyObject events) {
            return doOutput(context, events);
        }
    }
}
