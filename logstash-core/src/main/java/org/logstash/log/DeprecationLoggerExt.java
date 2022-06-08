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

import co.elastic.logstash.api.DeprecationLogger;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * JRuby extension to provide deprecation logger functionality to Ruby classes
 * */
@JRubyClass(name = "DeprecationLogger")
public class DeprecationLoggerExt extends RubyObject {

    private static final long serialVersionUID = 1L;

    private DeprecationLogger logger;

    public DeprecationLoggerExt(final Ruby runtime, final RubyClass metaClass) {
        super(runtime, metaClass);
    }

    DeprecationLoggerExt(final Ruby runtime, final RubyClass metaClass, final String loggerName) {
        super(runtime, metaClass);
        initialize(loggerName);
    }

    @JRubyMethod
    public DeprecationLoggerExt initialize(final ThreadContext context, final IRubyObject loggerName) {
        initialize(loggerName.asJavaString());
        return this;
    }

    private void initialize(final String loggerName) {
        logger = new DefaultDeprecationLogger(loggerName);
    }

    @JRubyMethod(name = "deprecated", required = 1, optional = 1)
    public IRubyObject rubyDeprecated(final ThreadContext context, final IRubyObject[] args) {
        if (args.length > 1) {
            logger.deprecated(args[0].toString(), args[1]);
        } else {
            logger.deprecated(args[0].toString());
        }
        return this;
    }
}
