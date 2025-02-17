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


package org.logstash.plugins.outputs;

import co.elastic.logstash.api.Codec;
import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.Output;
import co.elastic.logstash.api.PluginConfigSpec;
import co.elastic.logstash.api.PluginHelper;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;

/**
 * Java implementation of the "stdout" output plugin
 * */
@LogstashPlugin(name = "java_stdout")
public class Stdout implements Output {

    public static final PluginConfigSpec<Codec> CODEC_CONFIG =
            PluginConfigSpec.codecSetting("codec", "debug");

    private Codec codec;
    private OutputStream outputStream;
    private final CountDownLatch done = new CountDownLatch(1);
    private String id;

    /**
     * Required constructor.
     *
     * @param id            Plugin id
     * @param configuration Logstash Configuration
     * @param context       Logstash Context
     */
    public Stdout(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out);
    }

    Stdout(final String id, final Configuration configuration, final Context context, OutputStream targetStream) {
        this.id = id;
        this.outputStream = targetStream;
        codec = configuration.get(CODEC_CONFIG);
        if (codec == null) {
            throw new IllegalStateException("Unable to obtain codec");
        }
    }

    @Override
    public void output(final Collection<Event> events) {
        try {
            for (Event e : events) {
                codec.encode(e, outputStream);
            }
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void stop() {
        done.countDown();
    }

    @Override
    public void awaitStop() throws InterruptedException {
        done.await();
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return PluginHelper.commonOutputSettings(Collections.singletonList(CODEC_CONFIG));
    }

    @Override
    public String getId() {
        return id;
    }
}
