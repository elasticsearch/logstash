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

import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.InstanceVariables;
import org.logstash.RubyUtil;

import java.util.Locale;

import static org.logstash.log.SlowLoggerExt.toLong;

/**
 * JRuby extension, it's part of log4j wrapping for JRuby.
 */
@JRubyModule(name = "LogStash::Util::Loggable")
public final class LoggableExt {

    private LoggableExt() {
        // Ruby Module
    }

    @JRubyMethod(module = true)
    public static RubyModule included(final ThreadContext context, final IRubyObject recv,
        final IRubyObject clazz) {
        final RubyModule klass = (RubyModule) clazz;
        klass.defineAnnotatedMethods(LoggableExt.ClassMethods.class);
        return klass;
    }

    @JRubyMethod
    public static IRubyObject logger(final ThreadContext context, final IRubyObject self) {
        return self.getMetaClass().callMethod(context, "logger");
    }

    @JRubyMethod(name = "slow_logger", required = 4)
    public static IRubyObject slowLogger(final ThreadContext context, final IRubyObject self,
        final IRubyObject[] args) {
        return self.getMetaClass().callMethod(context, "slow_logger", args);
    }

    @JRubyMethod(name= "deprecation_logger")
    public static IRubyObject deprecationLogger(final ThreadContext context, final IRubyObject self) {
        return self.getMetaClass().callMethod(context, "deprecation_logger");
    }

    static String log4jName(final RubyModule self) {
        String name;
        if (self.getBaseName() == null) { // anonymous module/class
            RubyModule real = self;
            if (self instanceof RubyClass) {
                real = ((RubyClass) self).getRealClass();
            }
            name = real.getName(); // for anonymous: "#<Class:0xcafebabe>"
        } else {
            name = self.getName();
        }
        return name.replace("::", ".").toLowerCase(Locale.ENGLISH);
    }

    /**
     * Holds the {@link JRubyMethod}s class methods that the {@link LoggableExt} module binds
     * on classes that include it (and hence invoke
     * {@link LoggableExt#included(ThreadContext, IRubyObject, IRubyObject)}).
     */
    public static final class ClassMethods {

        private ClassMethods() {
            // Holder for JRuby Methods
        }

        @JRubyMethod(meta = true)
        public static IRubyObject logger(final ThreadContext context, final IRubyObject self) {
            final InstanceVariables instanceVariables;
            if (self instanceof RubyClass) {
                instanceVariables = ((RubyClass) self).getRealClass().getInstanceVariables();
            } else {
                instanceVariables = self.getInstanceVariables();
            }
            IRubyObject logger = instanceVariables.getInstanceVariable("logger");
            if (logger == null || logger.isNil()) {
                final String loggerName = log4jName((RubyModule) self);
                logger = RubyUtil.LOGGER.callMethod(context, "new", context.runtime.newString(loggerName));
                instanceVariables.setInstanceVariable("logger", logger);
            }
            return logger;
        }

        @JRubyMethod(name = "slow_logger", required = 4, meta = true)
        public static SlowLoggerExt slowLogger(final ThreadContext context,
            final IRubyObject self, final IRubyObject[] args) {
            final InstanceVariables instanceVariables = self.getInstanceVariables();
            IRubyObject logger = instanceVariables.getInstanceVariable("slow_logger");
            if (logger == null || logger.isNil()) {
                final String loggerName = log4jName((RubyModule) self);
                logger = new SlowLoggerExt(context.runtime, RubyUtil.SLOW_LOGGER, loggerName,
                        toLong(args[0]), toLong(args[1]), toLong(args[2]), toLong(args[3])
                );
                instanceVariables.setInstanceVariable("slow_logger", logger);
            }
            return (SlowLoggerExt) logger;
        }

        @JRubyMethod(name = "deprecation_logger", meta = true)
        public static IRubyObject deprecationLogger(final ThreadContext context, final IRubyObject self) {
            final InstanceVariables instanceVariables;
            if (self instanceof RubyClass) {
                instanceVariables = ((RubyClass) self).getRealClass().getInstanceVariables();
            } else {
                instanceVariables = self.getInstanceVariables();
            }
            IRubyObject logger = instanceVariables.getInstanceVariable("deprecation_logger");
            if (logger == null || logger.isNil()) {
                final String loggerName = log4jName((RubyModule) self);
                logger = new DeprecationLoggerExt(context.runtime, RubyUtil.DEPRECATION_LOGGER, loggerName);
                instanceVariables.setInstanceVariable("deprecation_logger", logger);
            }
            return logger;
        }
    }
}
