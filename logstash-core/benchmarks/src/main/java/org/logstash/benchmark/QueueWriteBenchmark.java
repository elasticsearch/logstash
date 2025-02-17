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


package org.logstash.benchmark;

import java.nio.file.Files;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import org.logstash.Event;
import org.logstash.Timestamp;
import org.logstash.ackedqueue.Queue;
import org.logstash.ackedqueue.Settings;
import org.logstash.ackedqueue.SettingsImpl;
import org.logstash.benchmark.singlewriterqueue.AppendOnlyQueue;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

@Warmup(iterations = 3, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 10, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Fork(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
public class QueueWriteBenchmark {

    private static final int EVENTS_PER_INVOCATION = 500_000;

    private static final Event EVENT = new Event();

    private Queue queue;

    private String path;

    private AppendOnlyQueue baselineQueue;
    private Path baselineQueueDirectory;
    private byte[] data;

    @Setup
    public void setUp() throws IOException, NoSuchAlgorithmException {
        final Settings settings = settings();
        EVENT.setField("Foo", "Bar");
        EVENT.setField("Foo1", "Bar1");
        EVENT.setField("Foo2", "Bar2");
        EVENT.setField("Foo3", "Bar3");
        EVENT.setField("Foo4", "Bar4");
        path = settings.getDirPath();
        queue = new Queue(settings);
        queue.open();

        setupBaselineQueue();
    }

    private void setupBaselineQueue() throws IOException, NoSuchAlgorithmException {
        final Path queuePath = FileSystems.getDefault().getPath("/tmp/queue");
        if (queuePath.toFile().exists()) {
            baselineQueueDirectory = queuePath;
        } else {
            baselineQueueDirectory = java.nio.file.Files.createDirectory(queuePath);
        }
        baselineQueue = new AppendOnlyQueue(baselineQueueDirectory.toString());
        data = generateRandomData(1024);
    }

    private static byte[] generateRandomData(int size) throws NoSuchAlgorithmException {
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        final byte[] res = new byte[size];
        random.nextBytes(res);
        return res;
    }

    @TearDown
    public void tearDown() throws IOException {
        queue.close();
        FileUtils.deleteDirectory(new File(path));

        baselineQueue.close();
        FileUtils.deleteDirectory(baselineQueueDirectory.toFile());
//        java.nio.file.Files.list(baselineQueueDirectory).forEach(p -> p.toFile().delete());
//        baselineQueueDirectory.toFile().delete();
    }

    @Benchmark
    @OperationsPerInvocation(EVENTS_PER_INVOCATION)
    public void baseline() throws IOException {
        for (int i = 0; i < EVENTS_PER_INVOCATION; i++) {
            baselineQueue.write(data);
        }
    }

    @Benchmark
    @OperationsPerInvocation(EVENTS_PER_INVOCATION)
    public final void pushToPersistedQueue() throws Exception {
        for (int i = 0; i < EVENTS_PER_INVOCATION; ++i) {
            final Event evnt = EVENT.clone();
            evnt.setTimestamp(Timestamp.now());
            queue.write(evnt);
        }
    }

    private static Settings settings() throws IOException {
        return SettingsImpl.fileSettingsBuilder(String.valueOf(Files.createTempDirectory(null)))
            .capacity(256 * 1024 * 1024)
            .queueMaxBytes(EVENTS_PER_INVOCATION * 1024 * 15)
            .checkpointMaxWrites(1024)
            .checkpointMaxAcks(1024)
            .elementClass(Event.class).build();
    }
}
