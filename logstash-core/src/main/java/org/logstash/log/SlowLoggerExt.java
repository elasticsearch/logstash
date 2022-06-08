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


package org.logstash.log;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.logstash.RubyUtil;

/**
 * JRuby extension to provide slow logger functionality to Ruby classes
 * */
@JRubyClass(name = "SlowLogger")
public class SlowLoggerExt extends RubyObject {

    private static final long serialVersionUID = 1L;

    private static final RubySymbol PLUGIN_PARAMS = RubyUtil.RUBY.newSymbol("plugin_params");
    private static final RubySymbol TOOK_IN_NANOS = RubyUtil.RUBY.newSymbol("took_in_nanos");
    private static final RubySymbol TOOK_IN_MILLIS = RubyUtil.RUBY.newSymbol("took_in_millis");
    private static final RubySymbol EVENT = RubyUtil.RUBY.newSymbol("event");
    private static final RubyNumeric NANO_TO_MILLI = RubyUtil.RUBY.newFixnum(1000000);

    private Logger slowLogger;
    private long warnThreshold;
    private long infoThreshold;
    private long debugThreshold;
    private long traceThreshold;

    public SlowLoggerExt(final Ruby runtime, final RubyClass metaClass) {
        super(runtime, metaClass);
    }

    SlowLoggerExt(final Ruby runtime, final RubyClass metaClass, final String loggerName,
                  final long warnThreshold, final long infoThreshold,
                  final long debugThreshold, final long traceThreshold) {
        super(runtime, metaClass);
        initialize(loggerName, warnThreshold, infoThreshold, debugThreshold, traceThreshold);
    }

    @JRubyMethod(required = 5)
    public SlowLoggerExt initialize(final ThreadContext context, final IRubyObject[] args) {
        initialize(args[0].asJavaString(), toLong(args[1]), toLong(args[2]), toLong(args[3]), toLong(args[4]));
        return this;
    }

    private void initialize(final String loggerName,
                            final long warnThreshold, final long infoThreshold,
                            final long debugThreshold, final long traceThreshold) {
        slowLogger = LogManager.getLogger("slowlog." + loggerName);
        this.warnThreshold = warnThreshold;
        this.infoThreshold = infoThreshold;
        this.debugThreshold = debugThreshold;
        this.traceThreshold = traceThreshold;
    }

    static long toLong(final IRubyObject value) {
        if (!(value instanceof RubyNumeric)) {
            throw RubyUtil.RUBY.newTypeError("Numeric expected, got " + value.getMetaClass());
        }
        return ((RubyNumeric) value).getLongValue();
    }

    private RubyHash asData(final ThreadContext context, final IRubyObject pluginParams,
                            final IRubyObject event, final IRubyObject durationNanos) {
        RubyHash data = RubyHash.newHash(context.runtime);
        data.put(PLUGIN_PARAMS, pluginParams);
        data.put(TOOK_IN_NANOS, durationNanos);
        data.put(TOOK_IN_MILLIS, ((RubyNumeric)durationNanos).div(context, NANO_TO_MILLI));
        data.put(EVENT, event.callMethod(context, "to_json"));
        return data;
    }

    @JRubyMethod(name = "on_event", required = 4)
    public IRubyObject onEvent(final ThreadContext context, final IRubyObject[] args) {
        String message = args[0].toString();
        long eventDurationNanos = ((RubyNumeric)args[3]).getLongValue();

        if (warnThreshold >= 0 && eventDurationNanos > warnThreshold) {
            slowLogger.warn(message, asData(context, args[1], args[2], args[3]));
        } else if (infoThreshold >= 0 && eventDurationNanos > infoThreshold) {
            slowLogger.info(message, asData(context, args[1], args[2], args[3]));
        } else if (debugThreshold >= 0 && eventDurationNanos > debugThreshold) {
            slowLogger.debug(message, asData(context, args[1], args[2], args[3]));
        } else if (traceThreshold >= 0 && eventDurationNanos > traceThreshold) {
            slowLogger.trace(message, asData(context, args[1], args[2], args[3]));
        }
        return context.nil;
    }

}
