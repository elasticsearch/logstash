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

import java.io.Closeable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.logstash.DLQEntry;
import org.logstash.Timestamp;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Comparator;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static org.logstash.common.io.DeadLetterQueueWriter.getSegmentPaths;

public final class DeadLetterQueueReader implements Closeable {
    private static final Logger logger = LogManager.getLogger(DeadLetterQueueReader.class);

    private RecordIOReader currentReader;
    private final Path queuePath;
    private final ConcurrentSkipListSet<Path> segments;
    private final WatchService watchService;

    public DeadLetterQueueReader(Path queuePath) throws IOException {
        this.queuePath = queuePath;
        this.watchService = FileSystems.getDefault().newWatchService();
        this.queuePath.register(watchService, ENTRY_CREATE, ENTRY_DELETE);
        this.segments = new ConcurrentSkipListSet<>(
                Comparator.comparingInt(DeadLetterQueueUtils::extractSegmentId)
        );
        segments.addAll(getSegmentPaths(queuePath).collect(Collectors.toList()));
    }

    public void seekToNextEvent(Timestamp timestamp) throws IOException {
        for (Path segment : segments) {
            Optional<RecordIOReader> optReader = openSegmentReader(segment);
            if (!optReader.isPresent()) {
                continue;
            }
            currentReader = optReader.get();

            byte[] event = currentReader.seekToNextEventPosition(timestamp, DeadLetterQueueReader::extractEntryTimestamp, Timestamp::compareTo);
            if (event != null) {
                return;
            }
        }
        if (currentReader != null) {
            currentReader.close();
            currentReader = null;
        }
    }

    private Optional<RecordIOReader> openSegmentReader(Path segment) throws IOException {
        if (!Files.exists(segment)) {
            return Optional.empty();
        }

        try {
            return Optional.of(new RecordIOReader(segment));
        } catch (NoSuchFileException ex) {
            logger.debug("Segment file {} was deleted by DLQ writer during DLQ reader opening", segment);
            // file was deleted by upstream process and segments list wasn't yet updated
            segments.remove(segment);
            return Optional.empty();
        }
    }

    private static Timestamp extractEntryTimestamp(byte[] serialized) {
        try {
            return DLQEntry.deserialize(serialized).getEntryTime();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private long pollNewSegments(long timeout) throws IOException, InterruptedException {
        long startTime = System.currentTimeMillis();
        WatchKey key = watchService.poll(timeout, TimeUnit.MILLISECONDS);
        if (key != null) {
            pollSegmentsOnWatch(key);
        }
        return System.currentTimeMillis() - startTime;
    }

    private void pollNewSegments() throws IOException {
        WatchKey key = watchService.poll();
        if (key != null) {
            pollSegmentsOnWatch(key);
        }
    }

    private void pollSegmentsOnWatch(WatchKey key) throws IOException {
        for (WatchEvent<?> watchEvent : key.pollEvents()) {
            if (watchEvent.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                segments.addAll(getSegmentPaths(queuePath).collect(Collectors.toList()));
            } else if (watchEvent.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
                final int oldSize = segments.size();
                segments.clear();
                segments.addAll(getSegmentPaths(queuePath).collect(Collectors.toList()));
                logger.debug("Notified of segment removal, switched from {} to {} segments", oldSize, segments.size());
            }
            key.reset();
        }
    }

    public DLQEntry pollEntry(long timeout) throws IOException, InterruptedException {
        byte[] bytes = pollEntryBytes(timeout);
        if (bytes == null) {
            return null;
        }
        return DLQEntry.deserialize(bytes);
    }

    byte[] pollEntryBytes() throws IOException, InterruptedException {
        return pollEntryBytes(100);
    }

    byte[] pollEntryBytes(long timeout) throws IOException, InterruptedException {
        long timeoutRemaining = timeout;
        if (currentReader == null) {
            timeoutRemaining -= pollNewSegments(timeout);
            // If no new segments are found, exit
            if (segments.isEmpty()) {
                logger.debug("No entries found: no segment files found in dead-letter-queue directory");
                return null;
            }
            Optional<RecordIOReader> optReader;
            do {
                final Path firstSegment;
                try {
                    firstSegment = segments.first();
                } catch (NoSuchElementException ex) {
                    // all elements were removed after the empty check
                    logger.debug("No entries found: no segment files found in dead-letter-queue directory");
                    return null;
                }

                optReader = openSegmentReader(firstSegment);
                if (optReader.isPresent()) {
                    currentReader = optReader.get();
                }
            } while (!optReader.isPresent());
        }

        byte[] event = currentReader.readEvent();
        if (event == null && currentReader.isEndOfStream()) {
            if (consumedAllSegments()) {
                pollNewSegments(timeoutRemaining);
            } else {
                currentReader.close();
                Optional<RecordIOReader> optReader = openNextExistingReader(currentReader.getPath());
                if (!optReader.isPresent()) {
                    // segments were all already deleted files, do a poll
                    pollNewSegments(timeoutRemaining);
                } else {
                    currentReader = optReader.get();
                    return pollEntryBytes(timeoutRemaining);
                }
            }
        }

        return event;
    }

    private boolean consumedAllSegments() {
        try {
            return currentReader.getPath().equals(segments.last());
        } catch (NoSuchElementException ex) {
            // last segment was removed while processing
            logger.debug("No last segment found, poll for new segments");
            return true;
        }
    }

    private Path nextExistingSegmentFile(Path currentSegmentPath) {
        Path nextExpectedSegment;
        boolean skip;
        do {
            nextExpectedSegment = segments.higher(currentSegmentPath);
            if (nextExpectedSegment != null && !Files.exists(nextExpectedSegment)) {
                segments.remove(nextExpectedSegment);
                skip = true;
            } else {
                skip = false;
            }
        } while (skip);
        return nextExpectedSegment;
    }

    public void setCurrentReaderAndPosition(Path segmentPath, long position) throws IOException {
        // If the provided segment Path exist, then set the reader to start from the supplied position
        Optional<RecordIOReader> optReader = openSegmentReader(segmentPath);
        if (optReader.isPresent()) {
            currentReader = optReader.get();
            currentReader.seekToOffset(position);
            return;
        }
        // Otherwise, set the current reader to be at the beginning of the next
        // segment.
        optReader = openNextExistingReader(segmentPath);
        if (optReader.isPresent()) {
            currentReader = optReader.get();
            return;
        }

        pollNewSegments();

        // give a second try after a re-load of segments from filesystem
        openNextExistingReader(segmentPath)
                .ifPresent(reader -> currentReader = reader);
    }

    private Optional<RecordIOReader> openNextExistingReader(Path segmentPath) throws IOException {
        Path next = nextExistingSegmentFile(segmentPath);
        if (next == null) {
            return Optional.empty();
        }

        do {
            Optional<RecordIOReader> optReader = openSegmentReader(next);
            if (optReader.isPresent()) {
                return optReader;
            }
            next = nextExistingSegmentFile(segmentPath);
        } while (next != null);

        return Optional.empty();
    }

    public Path getCurrentSegment() {
        return currentReader.getPath();
    }

    public long getCurrentPosition() {
        return currentReader.getChannelPosition();
    }

    @Override
    public void close() throws IOException {
        if (currentReader != null) {
            currentReader.close();
        }
        this.watchService.close();
    }
}
