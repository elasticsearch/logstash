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


import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.logstash.DLQEntry;
import org.logstash.Event;
import org.logstash.Timestamp;
import org.logstash.ackedqueue.StringElement;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.logstash.common.io.DeadLetterQueueTestUtils.MB;
import static org.logstash.common.io.RecordIOWriter.BLOCK_SIZE;
import static org.logstash.common.io.RecordIOWriter.RECORD_HEADER_SIZE;
import static org.logstash.common.io.RecordIOWriter.VERSION_SIZE;

public class DeadLetterQueueReaderTest {
    public static final int INTERNAL_FRAG_PAYLOAD_SIZE = BLOCK_SIZE - RECORD_HEADER_SIZE - 5;
    private Path dir;
    private int defaultDlqSize = 100_000_000; // 100mb

    private static final int PAD_FOR_BLOCK_SIZE_EVENT = 32490;

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private static String segmentFileName(int i) {
        return String.format(DeadLetterQueueWriter.SEGMENT_FILE_PATTERN, i);
    }

    @Before
    public void setUp() throws Exception {
        dir = temporaryFolder.newFolder().toPath();
    }

    @Test
    public void testReadFromTwoSegments() throws Exception {
        RecordIOWriter writer = null;

        for (int i = 0; i < 5; i++) {
            Path segmentPath = dir.resolve(segmentFileName(i));
            writer = new RecordIOWriter(segmentPath);
            for (int j = 0; j < 10; j++) {
                writer.writeEvent((new StringElement("" + (i * 10 + j))).serialize());
            }
            if (i < 4) {
                writer.close();
            }
        }

        DeadLetterQueueReader manager = new DeadLetterQueueReader(dir);

        for (int i = 0; i < 50; i++) {
            String first = StringElement.deserialize(manager.pollEntryBytes()).toString();
            assertThat(first, equalTo(String.valueOf(i)));
        }

        assertThat(manager.pollEntryBytes(), is(nullValue()));
        assertThat(manager.pollEntryBytes(), is(nullValue()));
        assertThat(manager.pollEntryBytes(), is(nullValue()));
        assertThat(manager.pollEntryBytes(), is(nullValue()));

        for (int j = 50; j < 60; j++) {
            writer.writeEvent((new StringElement(String.valueOf(j))).serialize());
        }

        for (int i = 50; i < 60; i++) {
            String first = StringElement.deserialize(manager.pollEntryBytes()).toString();
            assertThat(first, equalTo(String.valueOf(i)));
        }

        writer.close();

        Path segmentPath = dir.resolve(segmentFileName(5));
        writer = new RecordIOWriter(segmentPath);

        for (int j = 0; j < 10; j++) {
            writer.writeEvent((new StringElement(String.valueOf(j))).serialize());
        }


        for (int i = 0; i < 10; i++) {
            byte[] read = manager.pollEntryBytes();
            while (read == null) {
                read = manager.pollEntryBytes();
            }
            String first = StringElement.deserialize(read).toString();
            assertThat(first, equalTo(String.valueOf(i)));
        }


        manager.close();
    }


    // This test checks that polling after a block has been mostly filled with an event is handled correctly.
    @Test
    public void testRereadFinalBlock() throws Exception {
        Event event = createEventWithConstantSerializationOverhead(Collections.emptyMap());

        // Fill event with not quite enough characters to fill block. Fill event with valid RecordType characters - this
        // was the cause of https://github.com/elastic/logstash/issues/7868
        event.setField("message", generateMessageContent(32495));
        long startTime = System.currentTimeMillis();
        int messageSize = 0;
        try(DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 0; i < 2; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", String.valueOf(i), constantSerializationLengthTimestamp(startTime++));
                final int serializationLength = entry.serialize().length;
                assertThat("setup: serialized entry size...", serializationLength, is(lessThan(BLOCK_SIZE)));
                messageSize += serializationLength;
                writeManager.writeEntry(entry);
            }
            assertThat(messageSize, is(greaterThan(BLOCK_SIZE)));
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < 2;i++) {
                final DLQEntry dlqEntry = readManager.pollEntry(100);
                assertThat(String.format("read index `%s`", i), dlqEntry, is(notNullValue()));
                assertThat("", dlqEntry.getReason(), is(String.valueOf(i)));
            }
            final DLQEntry entryBeyondEnd = readManager.pollEntry(100);
            assertThat("read beyond end", entryBeyondEnd, is(nullValue()));
        }
    }

    @Test
    public void testSeek() throws Exception {
        Event event = new Event(Collections.emptyMap());
        long currentEpoch = System.currentTimeMillis();
        int TARGET_EVENT = 543;

        writeEntries(event, 0, 1000, currentEpoch);
        seekReadAndVerify(new Timestamp(currentEpoch + TARGET_EVENT),
                          String.valueOf(TARGET_EVENT));
    }


    @Test
    public void testSeekToStartOfRemovedLog() throws Exception {
        writeSegmentSizeEntries(3);
        Path startLog = dir.resolve("1.log");
        validateEntries(startLog, 1, 3, 1);
        startLog.toFile().delete();
        validateEntries(startLog, 2, 3, 1);
    }

    @Test
    public void testSeekToMiddleOfRemovedLog() throws Exception {
        writeSegmentSizeEntries(3);
        Path startLog = dir.resolve("1.log");
        startLog.toFile().delete();
        validateEntries(startLog, 2, 3, 32);
    }

    private void writeSegmentSizeEntries(int count) throws IOException {
        final Event event = createEventWithConstantSerializationOverhead();
        long startTime = System.currentTimeMillis();
        DLQEntry templateEntry = new DLQEntry(event, "1", "1", String.valueOf(0), constantSerializationLengthTimestamp(startTime));
        int size = templateEntry.serialize().length + RECORD_HEADER_SIZE + VERSION_SIZE;
        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, size, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 1; i <= count; i++) {
                writeManager.writeEntry(new DLQEntry(event, "1", "1", String.valueOf(i), constantSerializationLengthTimestamp(startTime++)));
            }
        }
    }


    private void validateEntries(Path firstLog, int startEntry, int endEntry, int startPosition) throws IOException, InterruptedException {
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            readManager.setCurrentReaderAndPosition(firstLog, startPosition);
            for (int i = startEntry; i <= endEntry; i++) {
                DLQEntry readEntry = readManager.pollEntry(100);
                assertThat(readEntry.getReason(), equalTo(String.valueOf(i)));
            }
        }
    }

    // Notes on these tests:
    //   These tests are designed to test specific edge cases where events end at block boundaries, hence the specific
    //    sizes of the char arrays being used to pad the events

    // This test tests for a single event that ends on a block boundary
    @Test
    public void testBlockBoundary() throws Exception {
        final int PAD_FOR_BLOCK_SIZE_EVENT = 32490;
        Event event = createEventWithConstantSerializationOverhead();
        char[] field = new char[PAD_FOR_BLOCK_SIZE_EVENT];
        Arrays.fill(field, 'e');
        event.setField("T", new String(field));
        Timestamp timestamp = constantSerializationLengthTimestamp();

        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 0; i < 2; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", "", timestamp);
                assertThat(entry.serialize().length + RECORD_HEADER_SIZE, is(BLOCK_SIZE));
                writeManager.writeEntry(entry);
            }
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < 2;i++) {
                readManager.pollEntry(100);
            }
        }
    }

    // This test has multiple messages, with a message ending on a block boundary
    @Test
    public void testBlockBoundaryMultiple() throws Exception {
        Event event = createEventWithConstantSerializationOverhead();
        char[] field = new char[7929];
        Arrays.fill(field, 'x');
        event.setField("message", new String(field));
        long startTime = System.currentTimeMillis();
        int messageSize = 0;
        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 1; i <= 5; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", "", constantSerializationLengthTimestamp(startTime++));
                messageSize += entry.serialize().length;
                writeManager.writeEntry(entry);
                if (i == 4){
                    assertThat(messageSize + (RECORD_HEADER_SIZE * 4), is(BLOCK_SIZE));
                }
            }
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < 5;i++) {
                readManager.pollEntry(100);
            }
        }
    }

    @Test
    public void testFlushAfterWriterClose() throws Exception {
        Event event = new Event();
        event.setField("T", generateMessageContent(PAD_FOR_BLOCK_SIZE_EVENT/8));
        Timestamp timestamp = new Timestamp();

        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, BLOCK_SIZE, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 0; i < 6; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", Integer.toString(i), timestamp);
                writeManager.writeEntry(entry);
            }
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < 6;i++) {
                DLQEntry entry = readManager.pollEntry(100);
                assertThat(entry.getReason(), is(String.valueOf(i)));
            }
        }
    }

    @Test
    public void testFlushAfterSegmentComplete() throws Exception {
        Event event = new Event();
        final int EVENTS_BEFORE_FLUSH = randomBetween(1, 32);
        event.setField("T", generateMessageContent(PAD_FOR_BLOCK_SIZE_EVENT));
        Timestamp timestamp = new Timestamp();

        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, BLOCK_SIZE * EVENTS_BEFORE_FLUSH, defaultDlqSize, Duration.ofHours(1))) {
            for (int i = 1; i < EVENTS_BEFORE_FLUSH; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", Integer.toString(i), timestamp);
                writeManager.writeEntry(entry);
            }

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                for (int i = 1; i < EVENTS_BEFORE_FLUSH; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry, is(nullValue()));
                }
            }

            writeManager.writeEntry(new DLQEntry(event, "", "", "flush event", timestamp));

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                for (int i = 1; i < EVENTS_BEFORE_FLUSH; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry.getReason(), is(String.valueOf(i)));
                }
            }
        }
    }

    @Test
    public void testMultiFlushAfterSegmentComplete() throws Exception {
        Event event = new Event();
        final int eventsInSegment = randomBetween(1, 32);
        // Write enough events to not quite complete a second segment.
        final int totalEventsToWrite = (2 * eventsInSegment) - 1;
        event.setField("T", generateMessageContent(PAD_FOR_BLOCK_SIZE_EVENT));
        Timestamp timestamp = new Timestamp();

        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, BLOCK_SIZE * eventsInSegment, defaultDlqSize, Duration.ofHours(1))) {
            for (int i = 1; i < totalEventsToWrite; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", Integer.toString(i), timestamp);
                writeManager.writeEntry(entry);
            }

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {

                for (int i = 1; i < eventsInSegment; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry.getReason(), is(String.valueOf(i)));
                }


                for (int i = eventsInSegment + 1; i < totalEventsToWrite; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry, is(nullValue()));
                }
            }

            writeManager.writeEntry(new DLQEntry(event, "", "", "flush event", timestamp));

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                for (int i = 1; i < totalEventsToWrite; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry.getReason(), is(String.valueOf(i)));
                }
            }
        }
    }

    @Test
    public void testFlushAfterDelay() throws Exception {
        Event event = new Event();
        int eventsPerBlock = randomBetween(1,16);
        int eventsToWrite = eventsPerBlock - 1;
        event.setField("T", generateMessageContent(PAD_FOR_BLOCK_SIZE_EVENT/eventsPerBlock));
        Timestamp timestamp = new Timestamp();

        System.out.println("events per block= " + eventsPerBlock);

        try(DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, BLOCK_SIZE, defaultDlqSize, Duration.ofSeconds(2))) {
            for (int i = 1; i < eventsToWrite; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", Integer.toString(i), timestamp);
                writeManager.writeEntry(entry);
            }

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                for (int i = 1; i < eventsToWrite; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry, is(nullValue()));
                }
            }

            Thread.sleep(3000);

            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                for (int i = 1; i < eventsToWrite; i++) {
                    DLQEntry entry = readManager.pollEntry(100);
                    assertThat(entry.getReason(), is(String.valueOf(i)));
                }
            }

        }
    }

    // This test tests for a single event that ends on a block and segment boundary
    @Test
    public void testBlockAndSegmentBoundary() throws Exception {
        Event event = createEventWithConstantSerializationOverhead();
        event.setField("T", generateMessageContent(PAD_FOR_BLOCK_SIZE_EVENT));
        Timestamp timestamp = constantSerializationLengthTimestamp();

        try(DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, BLOCK_SIZE, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 0; i < 2; i++) {
                DLQEntry entry = new DLQEntry(event, "", "", "", timestamp);
                assertThat(entry.serialize().length + RECORD_HEADER_SIZE, is(BLOCK_SIZE));
                writeManager.writeEntry(entry);
            }
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < 2;i++) {
                readManager.pollEntry(100);
            }
        }
    }

    @Test
    public void testWriteReadRandomEventSize() throws Exception {
        Event event = new Event(Collections.emptyMap());
        int maxEventSize = BLOCK_SIZE * 2; // 64kb
        int eventCount = 1024; // max = 1000 * 64kb = 64mb
        long startTime = System.currentTimeMillis();

        try(DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = 0; i < eventCount; i++) {
                event.setField("message", generateMessageContent((int)(Math.random() * (maxEventSize))));
                DLQEntry entry = new DLQEntry(event, "", "", String.valueOf(i), new Timestamp(startTime++));
                writeManager.writeEntry(entry);
            }
        }
        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            for (int i = 0; i < eventCount;i++) {
                DLQEntry entry = readManager.pollEntry(100);
                assertThat(entry.getReason(), is(String.valueOf(i)));
            }
        }
    }

    @Test
    public void testWriteStopSmallWriteSeekByTimestamp() throws Exception {
        int FIRST_WRITE_EVENT_COUNT = 100;
        int SECOND_WRITE_EVENT_COUNT = 100;
        int OFFSET = 200;

        Event event = new Event(Collections.emptyMap());
        long startTime = System.currentTimeMillis();

        writeEntries(event, 0, FIRST_WRITE_EVENT_COUNT, startTime);
        writeEntries(event, OFFSET, SECOND_WRITE_EVENT_COUNT, startTime + 1_000);

        seekReadAndVerify(new Timestamp(startTime + FIRST_WRITE_EVENT_COUNT),
                          String.valueOf(FIRST_WRITE_EVENT_COUNT));
    }

    @Test
    public void testWriteStopBigWriteSeekByTimestamp() throws Exception {
        int FIRST_WRITE_EVENT_COUNT = 100;
        int SECOND_WRITE_EVENT_COUNT = 2000;
        int OFFSET = 200;

        Event event = new Event(Collections.emptyMap());
        long startTime = System.currentTimeMillis();

        writeEntries(event, 0, FIRST_WRITE_EVENT_COUNT, startTime);
        writeEntries(event, OFFSET, SECOND_WRITE_EVENT_COUNT, startTime + 1_000);

        seekReadAndVerify(new Timestamp(startTime + FIRST_WRITE_EVENT_COUNT),
                          String.valueOf(FIRST_WRITE_EVENT_COUNT));
    }

    @Test
    public void testSeekByTimestampMoveAfterDeletedSegment() throws IOException, InterruptedException {
        final long startTime = 1646296760000L;
        final int eventsPerSegment = prepareFilledSegmentFiles(2, startTime);

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            // remove the first segment
            Files.delete(dir.resolve(segmentFileName(1)));

            //Exercise, seek in the middle of first segment
            final Timestamp seekTarget = new Timestamp(startTime + (eventsPerSegment / 2));
            reader.seekToNextEvent(seekTarget);

            // Verify, hit the first event of the second segment
            DLQEntry readEntry = reader.pollEntry(100);
            assertEquals("Must load first event of next available segment", readEntry.getReason(), String.format("%05d", eventsPerSegment));
            final Timestamp firstEventSecondSegmentTimestamp = new Timestamp(startTime + eventsPerSegment);
            assertEquals(firstEventSecondSegmentTimestamp, readEntry.getEntryTime());
        }
    }

    @Test
    public void testSeekByTimestampWhenAllSegmentsAreDeleted() throws IOException, InterruptedException {
        final long startTime = System.currentTimeMillis();
        final int eventsPerSegment = prepareFilledSegmentFiles(2, startTime);

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            // remove the first segment
            Files.delete(dir.resolve(segmentFileName(1)));
            Files.delete(dir.resolve(segmentFileName(2)));

            //Exercise, seek in the middle of first segment
            final Timestamp seekTarget = new Timestamp(startTime + (eventsPerSegment / 2));
            reader.seekToNextEvent(seekTarget);

            // Verify, hit the first event of the second segment
            DLQEntry readEntry = reader.pollEntry(100);
            assertNull("No entry is available after all segments are deleted", readEntry);
        }
    }

    /**
     * Tests concurrently reading and writing from the DLQ.
     * @throws Exception On Failure
     */
    @Test
    public void testConcurrentWriteReadRandomEventSize() throws Exception {
        final ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            final int maxEventSize = BLOCK_SIZE * 2;
            final int eventCount = 300;
            exec.submit(() -> {
                final Event event = new Event();
                long startTime = System.currentTimeMillis();
                try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(10))) {
                    for (int i = 0; i < eventCount; i++) {
                        event.setField(
                                "message",
                                generateMessageContent((int) (Math.random() * (maxEventSize)))
                        );
                        writeManager.writeEntry(
                                new DLQEntry(
                                        event, "", "", String.valueOf(i),
                                        new Timestamp(startTime++)
                                )
                        );
                    }
                } catch (final IOException ex) {
                    throw new IllegalStateException(ex);
                }
            });

            int i = 0;
            try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
                while(i < eventCount) {
                    DLQEntry entry = readManager.pollEntry(10_000L);
                    if (entry != null){
                        assertThat(entry.getReason(), is(String.valueOf(i)));
                        i++;
                    }
                }
            } catch (Exception e){
                throw new IllegalArgumentException("Failed to process entry number" + i, e);
            }
        } finally {
            exec.shutdown();
            if (!exec.awaitTermination(2L, TimeUnit.MINUTES)) {
                Assert.fail("Failed to shut down record writer");
            }
        }
    }

    @Test
    public void testReaderFindSegmentHoleAfterSimulatingRetentionPolicyClean() throws IOException, InterruptedException {
        final int eventsPerSegment = prepareFilledSegmentFiles(3);
        assertEquals(319, eventsPerSegment);

        int remainingEventsInSegment = eventsPerSegment;

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            // read the first event to initialize reader structures
            final DLQEntry dlqEntry = reader.pollEntry(1_000);
            assertEquals("00000", dlqEntry.getReason());
            remainingEventsInSegment--;

            // simulate a storage policy clean, drop the middle segment file
            final List<Path> allSegments = Files.list(dir)
                    .sorted(Comparator.comparingInt(DeadLetterQueueUtils::extractSegmentId))
                    .collect(Collectors.toList());
            assertThat(allSegments.size(), greaterThanOrEqualTo(2));
            Files.delete(allSegments.remove(0)); // tail segment
            Files.delete(allSegments.remove(0)); // the segment after

            // consume the first segment
            for (int i = 0; i < remainingEventsInSegment; i++) {
                reader.pollEntry(1_000);
            }

            // Exercise
            // consume the first event after the hole
            final DLQEntry entryAfterHole = reader.pollEntry(1_000);

            assertEquals(String.format("%05d", eventsPerSegment * 2), entryAfterHole.getReason());
        }
    }

    @Test
    public void testReaderWhenAllRemaningSegmentsAreRemoved() throws IOException, InterruptedException {
        int remainingEventsInSegment = prepareFilledSegmentFiles(3);

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            // read the first event to initialize reader structures
            final DLQEntry dlqEntry = reader.pollEntry(1_000);
            assertEquals("00000", dlqEntry.getReason());
            remainingEventsInSegment--;

            // simulate a retention policy clean, that drops the remaining segments
            Files.list(dir)
                    .sorted()
                    .skip(1)
                    .forEach(DeadLetterQueueReaderTest::deleteSegment);

            // consume the first segment
            for (int i = 0; i < remainingEventsInSegment; i++) {
                reader.pollEntry(1_000);
            }

            // Exercise
            // consume the first event after the hole
            final DLQEntry entryAfterHole = reader.pollEntry(1_000);
            assertNull(entryAfterHole);
        }
    }

    private static void deleteSegment(Path file) {
        try {
            Files.delete(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testSeekToMiddleWhileTheLogIsRemoved() throws IOException, InterruptedException {
        writeSegmentSizeEntries(3);

        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {

            // removes 2 segments simulating a retention policy action
            Files.delete(dir.resolve("1.log"));
            Files.delete(dir.resolve("2.log"));

            readManager.setCurrentReaderAndPosition(dir.resolve("1.log"), 1);

            DLQEntry readEntry = readManager.pollEntry(100);
            assertThat(readEntry.getReason(), equalTo(String.valueOf(3)));
        }
    }

    @Test
    public void testStoreReaderPositionAndRestart() throws IOException, InterruptedException {
        // write some data into a segment file
        Path segmentPath = dir.resolve(segmentFileName(0));
        RecordIOWriter writer = new RecordIOWriter(segmentPath);
        for (int j = 0; j < 10; j++) {
            writer.writeEvent((new StringElement("" + j)).serialize());
        }
        writer.close();

        // read the first event and save read position
        Path currentSegment;
        long currentPosition;
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("0", new String(rawStr, StandardCharsets.UTF_8));
            currentSegment = reader.getCurrentSegment();
            currentPosition = reader.getCurrentPosition();
        }

        // reopen the reader from the last saved position and read next element
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            reader.setCurrentReaderAndPosition(currentSegment, currentPosition);

            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("1", new String(rawStr, StandardCharsets.UTF_8));
        }
    }

    @Test
    public void testReaderWithBlockInternalFragmentation() throws IOException, InterruptedException {
        writeSegmentWithFirstBlockContainingInternalFragmentation();

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals(stringOf(INTERNAL_FRAG_PAYLOAD_SIZE, 'A'), new String(rawStr, StandardCharsets.UTF_8));

            rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("BBBBBBBBBB", new String(rawStr, StandardCharsets.UTF_8));
        }
    }

    private static String stringOf(int length, char ch) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(ch);
        }
        return sb.toString();
    }

    @Test
    public void testStoreReaderPositionWithBlocksWithInternalFragmentation() throws IOException, InterruptedException {
        writeSegmentWithFirstBlockContainingInternalFragmentation();

        // read the first event and save read position
        Path currentSegment;
        long currentPosition;
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals(stringOf(INTERNAL_FRAG_PAYLOAD_SIZE, 'A'), new String(rawStr, StandardCharsets.UTF_8));
            currentSegment = reader.getCurrentSegment();
            currentPosition = reader.getCurrentPosition();
        }

        // reopen the reader from the last saved position and read next element
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            reader.setCurrentReaderAndPosition(currentSegment, currentPosition);

            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("BBBBBBBBBB", new String(rawStr, StandardCharsets.UTF_8));
        }
    }

    @Test
    public void testStoreReaderPositionWithBlocksWithInternalFragmentationOnceMessageIsBiggerThenBlock() throws IOException, InterruptedException {
        final int payloadSize = INTERNAL_FRAG_PAYLOAD_SIZE + BLOCK_SIZE;
        byte[] almostFullBlockPayload = new byte[payloadSize];
        Arrays.fill(almostFullBlockPayload, (byte) 'A');
        Path segmentPath = dir.resolve(segmentFileName(0));
        RecordIOWriter writer = new RecordIOWriter(segmentPath);
        writer.writeEvent(almostFullBlockPayload);

        // write a second segment with small payload
        byte[] smallPayload = new byte[10];
        Arrays.fill(smallPayload, (byte) 'B');
        writer.writeEvent(smallPayload);

        writer.close();

        // read the first event and save read position
        Path currentSegment;
        long currentPosition;
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals(stringOf(payloadSize, 'A'), new String(rawStr, StandardCharsets.UTF_8));
            currentSegment = reader.getCurrentSegment();
            currentPosition = reader.getCurrentPosition();
        }

        // reopen the reader from the last saved position and read next element
        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(dir)) {
            reader.setCurrentReaderAndPosition(currentSegment, currentPosition);

            byte[] rawStr = reader.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("BBBBBBBBBB", new String(rawStr, StandardCharsets.UTF_8));
        }
    }

    private void writeSegmentWithFirstBlockContainingInternalFragmentation() throws IOException {
        byte[] almostFullBlockPayload = new byte[INTERNAL_FRAG_PAYLOAD_SIZE];
        Arrays.fill(almostFullBlockPayload, (byte) 'A');
        Path segmentPath = dir.resolve(segmentFileName(0));
        RecordIOWriter writer = new RecordIOWriter(segmentPath);
        writer.writeEvent(almostFullBlockPayload);

        // write a second segment with small payload
        byte[] smallPayload = new byte[10];
        Arrays.fill(smallPayload, (byte) 'B');
        writer.writeEvent(smallPayload);

        writer.close();
    }

    /**
     * Produces a {@link Timestamp} whose epoch milliseconds is _near_ the provided value
     * such that the result will have a constant serialization length of 24 bytes.
     *
     * If the provided epoch millis is exactly a whole second with no remainder, one millisecond
     * is added to the value to ensure that there are remainder millis.
     *
     * @param millis
     * @return
     */
    static Timestamp constantSerializationLengthTimestamp(long millis) {
        if ( millis % 1000 == 0) { millis += 1; }

        final Timestamp timestamp = new Timestamp(millis);
        assertThat(String.format("pre-validation: expected timestamp to serialize to exactly 24 bytes, got `%s`", timestamp),
                   timestamp.serialize().length, is(24));
        return new Timestamp(millis);
    }

    private Timestamp constantSerializationLengthTimestamp() {
        return constantSerializationLengthTimestamp(System.currentTimeMillis());
    }

    private static Timestamp constantSerializationLengthTimestamp(final Timestamp basis) {
        return constantSerializationLengthTimestamp(basis.toEpochMilli());
    }

    /**
     * Because many of the tests here rely on _exact_ alignment of serialization byte size,
     * and the {@link Timestamp} has a variable-sized serialization length, we need a way to
     * generated events whose serialization length will not vary depending on the millisecond
     * in which the test was run.
     *
     * This method uses the normal method of creating an event, and ensures that the value of
     * the timestamp field will serialize to a constant length, truncating precision and
     * possibly shifting the value to ensure that there is sub-second remainder millis.
     *
     * @param data
     * @return
     */
    static Event createEventWithConstantSerializationOverhead(final Map<String, Object> data) {
        final Event event = new Event(data);

        final Timestamp existingTimestamp = event.getTimestamp();
        if (existingTimestamp != null) {
            event.setTimestamp(constantSerializationLengthTimestamp(existingTimestamp));
        }

        return event;
    }

    private static Event createEventWithConstantSerializationOverhead() {
        return createEventWithConstantSerializationOverhead(Collections.emptyMap());
    }

    private int randomBetween(int from, int to){
        Random r = new Random();
        return r.nextInt((to - from) + 1) + from;
    }

    static String generateMessageContent(int size) {
        char[] valid = new char[RecordType.values().length + 1];
        int j = 0;
        valid[j] = 'x';
        for (RecordType type : RecordType.values()){
            valid[j++] = (char)type.toByte();
        }
        Random random = new Random();
        char fillWith = valid[random.nextInt(valid.length)];

        char[] fillArray = new char[size];
        Arrays.fill(fillArray, fillWith);
        return new String(fillArray);
    }

    private void seekReadAndVerify(final Timestamp seekTarget, final String expectedValue) throws Exception {
        try(DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir)) {
            readManager.seekToNextEvent(seekTarget);
            DLQEntry readEntry = readManager.pollEntry(100);
            assertThat(readEntry.getReason(), equalTo(expectedValue));
            assertThat(readEntry.getEntryTime().toString(), equalTo(seekTarget.toString()));
        }
    }

    private void writeEntries(final Event event, int offset, final int numberOfEvents, long startTime) throws IOException {
        try (DeadLetterQueueWriter writeManager = new DeadLetterQueueWriter(dir, 10 * 1024 * 1024, defaultDlqSize, Duration.ofSeconds(1))) {
            for (int i = offset; i <= offset + numberOfEvents; i++) {
                DLQEntry entry = new DLQEntry(event, "foo", "bar", String.valueOf(i), new Timestamp(startTime++));
                writeManager.writeEntry(entry);
            }
        }
    }

    private int prepareFilledSegmentFiles(int segments) throws IOException {
        return prepareFilledSegmentFiles(segments, System.currentTimeMillis());
    }

    private int prepareFilledSegmentFiles(int segments, long start) throws IOException {
        final Event event = createEventWithConstantSerializationOverhead(Collections.emptyMap());
        event.setField("message", generateMessageContent(32479));

        DLQEntry entry = new DLQEntry(event, "", "", String.format("%05d", 1), constantSerializationLengthTimestamp(start));
        assertEquals("Serialized dlq entry + header MUST be 32Kb (size of a block)", BLOCK_SIZE, entry.serialize().length + 13);

        final int maxSegmentSize = 10 * MB;
        final int loopPerSegment = (int) Math.floor((maxSegmentSize - 1.0) / BLOCK_SIZE);
        try (DeadLetterQueueWriter writer = new DeadLetterQueueWriter(dir, maxSegmentSize, defaultDlqSize, Duration.ofSeconds(1))) {
            final int loops = loopPerSegment * segments;
            for (int i = 0; i < loops; i++) {
                entry = new DLQEntry(event, "", "", String.format("%05d", i), constantSerializationLengthTimestamp(start++));
                writer.writeEntry(entry);
            }
        }

        assertEquals(segments, Files.list(dir).count());
        return loopPerSegment;
    }

    @Test
    public void testRestartFromCommitPointRealData() throws IOException, InterruptedException, URISyntaxException {
        URL url = this.getClass().getResource("1.log");
        Path path = Paths.get(url.toURI());

        try (DeadLetterQueueReader reader = new DeadLetterQueueReader(path.getParent())) {
            reader.setCurrentReaderAndPosition(path, 0x3593F0);

            for (int i = 0; i < 10_000 - 3_376; i++) {
                byte[] rawStr = reader.pollEntryBytes();
                assertNotNull(rawStr);
                assertThat(new String(rawStr, StandardCharsets.UTF_8), containsString("Could not index event to Elasticsearch. status: 400"));
            }
        }
    }

    @Test
    public void testReaderWithoutSinceDbAndNoReadOperationDoneThenCloseDoesntCreateAnySinceDBFile() throws IOException {
        DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir, true, 10);
        readManager.close();

        Set<File> sincedbs = listSincedbFiles();
        assertEquals("No sincedb file should be present", 0, sincedbs.size());
    }

    private Set<File> listSincedbFiles() throws IOException {
        return Files.list(dir)
                .filter(file -> file.getFileName().toString().equals("sincedb"))
                .map(Path::toFile)
                .collect(Collectors.toSet());
    }

    @Test
    public void testReaderCreatesASinceDBFileOnCloseAfterReadSomeEvents() throws IOException, InterruptedException {
        // write some data into a segment file
        Path segmentPath = dir.resolve(segmentFileName(0));
        RecordIOWriter writer = new RecordIOWriter(segmentPath);
        for (int j = 0; j < 10; j++) {
            writer.writeEvent((new StringElement("" + j)).serialize());
        }
        writer.close();

        try (DeadLetterQueueReader readManager = new DeadLetterQueueReader(dir, true, 10)) {
            byte[] rawStr = readManager.pollEntryBytes();
            assertNotNull(rawStr);
            assertEquals("0", new String(rawStr, StandardCharsets.UTF_8));
        }

        Set<File> sincedbs = listSincedbFiles();
        assertEquals("Sincedb file must be present", 1, sincedbs.size());

        DeadLetterQueueSinceDB sinceDB = DeadLetterQueueSinceDB.load(dir);
        assertNotNull(sinceDB.getCurrentSegment());
        assertEquals("0.log", sinceDB.getCurrentSegment().getFileName().toString());
        assertEquals(VERSION_SIZE + RECORD_HEADER_SIZE + 1, sinceDB.getOffset());
    }
}
