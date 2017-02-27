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

import org.logstash.Timestamp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import static org.logstash.common.io.RecordIOWriter.BLOCK_SIZE;
import static org.logstash.common.io.RecordIOWriter.RECORD_HEADER_SIZE;
import static org.logstash.common.io.RecordIOWriter.VERSION;
import static org.logstash.common.io.RecordIOWriter.VERSION_SIZE;

/**
 */
public class RecordIOReader {

    private final FileChannel channel;
    private final ByteBuffer currentBlock;
<<<<<<< HEAD
    private int currentBlockSizeReadFromChannel;
    private final Path path;
    private long channelPosition;
=======
    private final Path path;
    private boolean endOfStream;
>>>>>>> introduce recordio

    public RecordIOReader(Path path) throws IOException {
        this.path = path;
        this.channel = FileChannel.open(path, StandardOpenOption.READ);
        this.currentBlock = ByteBuffer.allocate(BLOCK_SIZE);
<<<<<<< HEAD
        this.currentBlockSizeReadFromChannel = 0;
        ByteBuffer versionBuffer = ByteBuffer.allocate(1);
        this.channel.read(versionBuffer);
        versionBuffer.rewind();
        if (versionBuffer.get() != VERSION) {
            throw new RuntimeException("Invalid file. check version");
        }
        this.channelPosition = this.channel.position();
    }

    public Path getPath() {
        return path;
    }

    public void seekToBlock(int bid) throws IOException {
        seekToOffset(bid * BLOCK_SIZE + VERSION_SIZE);
    }

    public void seekToOffset(long channelOffset) throws IOException {
        currentBlock.rewind();
        currentBlockSizeReadFromChannel = 0;
        channel.position(channelOffset);
        channelPosition = channel.position();
    }

    public <T> byte[] seekToNextEventPosition(T target, Function<byte[], T> keyExtractor, Comparator<T> keyComparator) throws IOException {
        int matchingBlock;
        int lowBlock = 0;
        int highBlock = (int) (channel.size() - VERSION_SIZE) / BLOCK_SIZE;

        if (highBlock == 0) {
            return null;
        }

        while (lowBlock < highBlock) {
            int middle = (int) Math.ceil((highBlock + lowBlock) / 2.0);
            seekToBlock(middle);
            T found = keyExtractor.apply(readEvent());
            int compare = keyComparator.compare(found, target);
            if (compare > 0) {
                highBlock = middle - 1;
            } else if (compare < 0) {
                lowBlock = middle;
            } else {
                matchingBlock = middle;
                break;
            }
        }
        matchingBlock = lowBlock;

        // now sequential scan to event
        seekToBlock(matchingBlock);
        int currentPosition = 0;
        int compare = -1;
        byte[] event = null;
        while (compare < 0) {
            currentPosition = currentBlock.position();
            event = readEvent();
            if (event == null) {
                return null;
            }
            compare = keyComparator.compare(keyExtractor.apply(event), target);
        }
        currentBlock.position(currentPosition);
        return event;
    }

    public long getChannelPosition() throws IOException {
        return channelPosition;
    }

    /**
     *
     * @param rewind
     * @throws IOException
     */
    void consumeBlock(boolean rewind) throws IOException {
        if (rewind) {
            currentBlockSizeReadFromChannel = 0;
            currentBlock.rewind();
        } else if (currentBlockSizeReadFromChannel == BLOCK_SIZE) {
            // already read enough, no need to read more
            return;
        }
        int originalPosition = currentBlock.position();
        int read = channel.read(currentBlock);
        currentBlockSizeReadFromChannel += (read > 0) ? read : 0;
        currentBlock.position(originalPosition);
    }

    /**
     * basically, is last block
     * @return
     */
    public boolean isEndOfStream() {
        return currentBlockSizeReadFromChannel < BLOCK_SIZE;
    }

    /**
     *
     */
     int seekToStartOfEventInBlock() throws IOException {
         while (true) {
             RecordType type = RecordType.fromByte(currentBlock.array()[currentBlock.arrayOffset() + currentBlock.position()]);
             if (RecordType.COMPLETE.equals(type) || RecordType.START.equals(type)) {
                 return currentBlock.position();
             } else if (RecordType.END.equals(type)) {
                 RecordHeader header = RecordHeader.get(currentBlock);
                 currentBlock.position(currentBlock.position() + header.getSize());
             } else {
                 return -1;
             }
         }
    }

    /**
     *
     * @return true if ready to read event, false otherwise
     * @throws IOException
     */
    boolean consumeToStartOfEvent() throws IOException {
        // read and seek to start of event
        consumeBlock(false);
        while (true) {
            int eventStartPosition = seekToStartOfEventInBlock();
            if (eventStartPosition < 0) {
                if (isEndOfStream()) {
                    return false;
                } else {
                    consumeBlock(true);
                }
            } else {
                return true;
            }
        }
    }

    private void maybeRollToNextBlock() throws IOException {
        // check block position state
        if (currentBlock.remaining() < RECORD_HEADER_SIZE + 1) {
            consumeBlock(true);
        }
    }

    private void getRecord(ByteBuffer buffer, RecordHeader header) throws IOException {
        Checksum computedChecksum = new CRC32();
        computedChecksum.update(currentBlock.array(), currentBlock.position(), header.getSize());

        if ((int) computedChecksum.getValue() != header.getChecksum()) {
            throw new RuntimeException("invalid checksum of record");
        }

        buffer.put(currentBlock.array(), currentBlock.position(), header.getSize());
        currentBlock.position(currentBlock.position() + header.getSize());
    }

    /**
     * @return
     * @throws IOException
     */
    public byte[] readEvent() throws IOException {
        try {
            if (channel.isOpen() == false || consumeToStartOfEvent() == false) {
                return null;
            }
            RecordHeader header = RecordHeader.get(currentBlock);
            int cumReadSize = 0;
            int bufferSize = header.getTotalEventSize().orElseGet(header::getSize);
            ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
            getRecord(buffer, header);
            cumReadSize += header.getSize();
            while (cumReadSize < bufferSize) {
                maybeRollToNextBlock();
                RecordHeader nextHeader = RecordHeader.get(currentBlock);
                getRecord(buffer, nextHeader);
                cumReadSize += nextHeader.getSize();
            }
            return buffer.array();
        } catch (ClosedByInterruptException e) {
            return null;
        } finally {
            if (channel.isOpen()) {
                channelPosition = channel.position();
            }
        }
=======
        this.endOfStream = true;
    }

    private void seekNextBlock() throws IOException {
        seekNextBlock(false);
    }

    private void seekNextBlock(boolean fresh) throws IOException {
        long prev = channel.position();
        int keepPosition;
        if (fresh) {
            keepPosition = 0;
        } else if (endOfStream && currentBlock.hasRemaining()) {
            keepPosition = currentBlock.position();
        } else {
            keepPosition = 0;
        }
        currentBlock.position(0);
        if (channel.read(currentBlock) < BLOCK_SIZE) {
            endOfStream = true;
            channel.position(prev);
        } else {
            endOfStream = false;
        }
        currentBlock.rewind();
        currentBlock.position(keepPosition);
    }

    public void seekNextBlock(int bid) throws IOException {
        currentBlock.position(currentBlock.limit());
        channel.position(bid * BLOCK_SIZE);
        seekNextBlock(true);
    }

    public Path getPath() {
        return path;
    }

    public boolean isEndOfStream() {
        return endOfStream;
    }

    /**
     * TODO(talevy): split out seeking to first record and/or end of buffer vs. actually reading the record
     * @return
     * @throws IOException
     */
    public byte[] readRecord() throws IOException {
        if (endOfStream) {
            seekNextBlock();
        }
        if (!currentBlock.hasRemaining() || currentBlock.remaining() < RECORD_HEADER_SIZE + 1) {
            return null;
        }
        // read header
        RecordType type = RecordType.fromByte(currentBlock.get());

        final int totalSize;
        int size;
        int cumReadSize = 0;
        if (type == RecordType.START) {
            size = currentBlock.getInt();
            totalSize = currentBlock.getInt();
        } else if (type == RecordType.COMPLETE) {
            totalSize = currentBlock.getInt();
            size = totalSize;
        } else if (type == RecordType.MIDDLE) {
            seekNextBlock(true);
            return readRecord();
        } else if (type == RecordType.END){
            size = currentBlock.getInt();
            currentBlock.position(currentBlock.position() + size);
            return readRecord();
        } else {
            currentBlock.position(currentBlock.position() - 1);
            return null;
        }
        ByteBuffer buffer = ByteBuffer.allocate(totalSize);
        buffer.put(currentBlock.array(), currentBlock.position(), size);
        currentBlock.position(currentBlock.position() + size);
        cumReadSize += size;

        if (!currentBlock.hasRemaining()) {
            seekNextBlock();
        }

        while (cumReadSize < totalSize) {
            type = RecordType.fromByte(currentBlock.get());
            if (type == null) {
                break;
            }
            size = currentBlock.getInt();
            buffer.put(currentBlock.array(), currentBlock.position(), size);
            currentBlock.position(currentBlock.position() + size);
            cumReadSize += size;
            if (!currentBlock.hasRemaining() && type != RecordType.END) {
                seekNextBlock();
            }
        }
        return buffer.array();
>>>>>>> introduce recordio
    }

    public void close() throws IOException {
        channel.close();
    }
}
