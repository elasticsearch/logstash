/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.logstash.common.io;

import org.logstash.DLQEntry;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static org.logstash.common.io.DeadLetterQueueWriteManager.getSegmentPaths;

public class DeadLetterQueueReadManager {

    private RecordIOReader currentReader;
    private final Path queuePath;
    private final ConcurrentSkipListSet<Path> segments;
    private final WatchService watchService;

    public DeadLetterQueueReadManager(Path queuePath) throws Exception {
        this.queuePath = queuePath;
        this.watchService = FileSystems.getDefault().newWatchService();
        this.queuePath.register(watchService, ENTRY_CREATE, ENTRY_DELETE);
        this.segments = new ConcurrentSkipListSet<>((p1, p2) -> {
            Function<Path, Integer> id = (p) -> Integer.parseInt(p.getFileName().toString().split("\\.")[0]);
            return id.apply(p1).compareTo(id.apply(p2));
        });

        segments.addAll(getSegmentPaths(queuePath).collect(Collectors.toList()));
    }

    private long pollNewSegments(long timeout) throws IOException, InterruptedException {
        long startTime = System.currentTimeMillis();
        WatchKey key = watchService.poll(timeout, TimeUnit.MILLISECONDS);
        if (key != null) {
            for (WatchEvent<?> watchEvent : key.pollEvents()) {
                if (watchEvent.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                    segments.addAll(getSegmentPaths(queuePath).collect(Collectors.toList()));
                }
                key.reset();
            }
        }
        return System.currentTimeMillis() - startTime;
    }

    public DLQEntry pollEntry(long timeout) throws IOException, InterruptedException {
        return DLQEntry.deserialize(pollRecord(timeout));
    }

    byte[] pollRecord() throws IOException, InterruptedException {
        return pollRecord(100);
    }

    byte[] pollRecord(long timeout) throws IOException, InterruptedException {
        long timeoutRemaining = timeout;
        if (currentReader == null) {
            timeoutRemaining -= pollNewSegments(timeout);
            currentReader = new RecordIOReader(segments.first());
        }

        byte[] event = currentReader.readRecord();
        if (event == null && currentReader.isEndOfStream()) {
            if (currentReader.getPath().equals(segments.last())) {
                pollNewSegments(timeoutRemaining);
            } else {
                currentReader.close();
                currentReader = new RecordIOReader(segments.higher(currentReader.getPath()));
                return pollRecord(timeoutRemaining);
            }
        }

        return event;
    }

    public void close() throws IOException {
        if (currentReader != null) {
            currentReader.close();
        }
    }
}
