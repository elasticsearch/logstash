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


package org.logstash.instrument.metrics;

import co.elastic.logstash.api.TimerMetric;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyException;
import org.jruby.RubyFixnum;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.logstash.RubyUtil;

@JRubyClass(name = "Metric")
public final class MetricExt extends AbstractSimpleMetricExt {

    private static final long serialVersionUID = 1L;

    public static final RubySymbol COUNTER = RubyUtil.RUBY.newSymbol("counter");

    public static final RubySymbol TIMER = RubyUtil.RUBY.newSymbol("timer");
    public static final RubySymbol REPORT_UNTRACKED = RubyUtil.RUBY.newSymbol("report_untracked");

    private static final RubyFixnum ONE = RubyUtil.RUBY.newFixnum(1);

    private static final RubySymbol INCREMENT = RubyUtil.RUBY.newSymbol("increment");

    private static final RubySymbol DECREMENT = RubyUtil.RUBY.newSymbol("decrement");

    private static final RubySymbol GAUGE = RubyUtil.RUBY.newSymbol("gauge");

    private static final RubySymbol SET = RubyUtil.RUBY.newSymbol("set");

    private transient IRubyObject collector;

    public MetricExt(final Ruby runtime, final RubyClass metaClass) {
        super(runtime, metaClass);
    }

    @JRubyMethod(name = "validate_key!", meta = true)
    public static IRubyObject validateKey(final ThreadContext context, final IRubyObject recv,
        final IRubyObject key) {
        validateName(context, key, RubyUtil.METRIC_NO_KEY_PROVIDED_CLASS);
        return context.nil;
    }

    public static void validateName(final ThreadContext context, final IRubyObject key,
        final RubyClass exception) {
        if (key.isNil() ||
            (key instanceof RubySymbol && ((RubySymbol) key).empty_p(context).isTrue())
            || (key instanceof RubyString && ((RubyString) key).isEmpty())) {
            throw context.runtime.newRaiseException(exception, null);
        }
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject collector) {
        this.collector = collector;
        return this;
    }

    public IRubyObject increment(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key) {
        return increment(context, namespace, key, ONE);
    }

    public IRubyObject increment(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key, final IRubyObject value) {
        MetricExt.validateKey(context, null, key);
        return collector.callMethod(
            context, "push", new IRubyObject[]{namespace, key, COUNTER, INCREMENT, value}
        );
    }

    public IRubyObject decrement(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key) {
        return decrement(context, namespace, key, ONE);
    }

    public IRubyObject decrement(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key, final IRubyObject value) {
        MetricExt.validateKey(context, null, key);
        return collector.callMethod(
            context, "push", new IRubyObject[]{namespace, key, COUNTER, DECREMENT, value}
        );
    }

    @Override
    protected IRubyObject doDecrement(final ThreadContext context, final IRubyObject[] args) {
        if (args.length == 2) {
            return decrement(context, args[0], args[1], ONE);
        } else {
            return decrement(context, args[0], args[1], args[2]);
        }
    }

    @Override
    protected IRubyObject getCollector(final ThreadContext context) {
        return collector;
    }

    @Override
    protected IRubyObject doIncrement(final ThreadContext context, final IRubyObject[] args) {
        if (args.length == 2) {
            return increment(context, args[0], args[1]);
        } else {
            return increment(context, args[0], args[1], args[2]);
        }
    }

    @Override
    protected IRubyObject getGauge(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key, final IRubyObject value) {
        MetricExt.validateKey(context, null, key);
        return collector.callMethod(
            context, "push", new IRubyObject[]{namespace, key, GAUGE, SET, value}
        );
    }

    @Override
    protected IRubyObject doReportTime(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key, final IRubyObject duration) {
        MetricExt.validateKey(context, null, key);
        return collector.callMethod(
            context, "push", new IRubyObject[]{namespace, key, TIMER, REPORT_UNTRACKED, duration}
        );
    }

    @Override
    protected IRubyObject doTime(final ThreadContext context, final IRubyObject namespace,
        final IRubyObject key, final Block block) {
        MetricExt.validateKey(context, null, key);

        final TimerMetric timer = this.collector.callMethod(context, "get", new IRubyObject[]{namespace, key, TIMER}).toJava(TimerMetric.class);
        if (!block.isGiven()) {
            return MetricExt.TimedExecution.create(timer.begin());
        }
        return timer.time(() -> block.call(context));
    }

    @Override
    protected NamespacedMetricExt createNamespaced(final ThreadContext context,
        final IRubyObject name) {
        validateName(context, name, RubyUtil.METRIC_NO_NAMESPACE_PROVIDED_CLASS);
        return NamespacedMetricExt.create(
            this,
            name instanceof RubyArray ? (RubyArray) name : RubyArray.newArray(context.runtime, name)
        );
    }

    @JRubyClass(name = "TimedExecution")
    public static final class TimedExecution extends RubyObject {

        private static final long serialVersionUID = 1L;

        private TimerMetric.Committer committer;

        public static MetricExt.TimedExecution create(final TimerMetric.Committer timerMetricCommitter) {
            final ThreadContext context = RubyUtil.RUBY.getCurrentContext();
            final MetricExt.TimedExecution res =
                new MetricExt.TimedExecution(RubyUtil.RUBY, RubyUtil.TIMED_EXECUTION_CLASS);
            res.committer = timerMetricCommitter;
            return res;
        }

        @JRubyMethod
        public RubyFixnum stop(final ThreadContext context) {
            final long executionTime = committer.commit();
            return RubyFixnum.newFixnum(context.runtime, executionTime);
        }

        public TimedExecution(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "MetricException")
    public static class MetricException extends RubyException {

        private static final long serialVersionUID = 1L;

        public MetricException(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "MetricNoKeyProvided", parent = "MetricException")
    public static final class MetricNoKeyProvided extends MetricException {

        private static final long serialVersionUID = 1L;

        public MetricNoKeyProvided(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "MetricNoBlockProvided", parent = "MetricException")
    public static final class MetricNoBlockProvided extends MetricException {

        private static final long serialVersionUID = 1L;

        public MetricNoBlockProvided(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "MetricNoNamespaceProvided", parent = "MetricException")
    public static final class MetricNoNamespaceProvided extends MetricException {

        private static final long serialVersionUID = 1L;

        public MetricNoNamespaceProvided(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }
}
