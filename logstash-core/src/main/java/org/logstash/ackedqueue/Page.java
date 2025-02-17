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


package org.logstash.ackedqueue;

import com.google.common.primitives.Ints;
import java.io.Closeable;
import java.io.IOException;
import java.util.BitSet;
import org.codehaus.commons.nullanalysis.NotNull;
import org.logstash.ackedqueue.io.CheckpointIO;
import org.logstash.ackedqueue.io.PageIO;

/**
 * Represents persistent queue Page metadata, like the page number, the minimum sequence number contained in the page,
 * the status of the page (writeable or not).
 * */
public final class Page implements Closeable {
    protected final int pageNum;
    protected long minSeqNum; // TODO: see if we can make it final?
    protected int elementCount;
    protected long firstUnreadSeqNum;
    protected final Queue queue;
    protected final PageIO pageIO;
    private boolean writable;

    // bit 0 is minSeqNum
    // TODO: go steal LocalCheckpointService in feature/seq_no from ES
    // TODO: https://github.com/elastic/elasticsearch/blob/feature/seq_no/core/src/main/java/org/elasticsearch/index/seqno/LocalCheckpointService.java
    protected final BitSet ackedSeqNums;
    protected Checkpoint lastCheckpoint;

    public Page(int pageNum, Queue queue, long minSeqNum, int elementCount, long firstUnreadSeqNum, BitSet ackedSeqNums, @NotNull PageIO pageIO, boolean writable) {
        this.pageNum = pageNum;
        this.queue = queue;

        this.minSeqNum = minSeqNum;
        this.elementCount = elementCount;
        this.firstUnreadSeqNum = firstUnreadSeqNum;
        this.ackedSeqNums = ackedSeqNums;
        this.lastCheckpoint = new Checkpoint(0, 0, 0, 0, 0);
        this.pageIO = pageIO;
        this.writable = writable;

        assert this.pageIO != null : "invalid null pageIO";
    }

    public String toString() {
        return "pageNum=" + this.pageNum + ", minSeqNum=" + this.minSeqNum + ", elementCount=" + this.elementCount + ", firstUnreadSeqNum=" + this.firstUnreadSeqNum;
    }

    /**
     * @param limit the maximum number of elements to read, actual number readcan be smaller
     * @return {@link SequencedList} collection of serialized elements read
     * @throws IOException if an IO error occurs
     */
    public SequencedList<byte[]> read(int limit) throws IOException {
        // first make sure this page is activated, activating previously activated is harmless
        this.pageIO.activate();

        SequencedList<byte[]> serialized = this.pageIO.read(this.firstUnreadSeqNum, limit);
        assert serialized.getSeqNums().get(0) == this.firstUnreadSeqNum :
            String.format("firstUnreadSeqNum=%d != first result seqNum=%d", this.firstUnreadSeqNum, serialized.getSeqNums().get(0));

        this.firstUnreadSeqNum += serialized.getElements().size();

        return serialized;
    }

    public void write(byte[] bytes, long seqNum, int checkpointMaxWrites) throws IOException {
        if (! this.writable) {
            throw new IllegalStateException(String.format("page=%d is not writable", this.pageNum));
        }

        this.pageIO.write(bytes, seqNum);

        if (this.minSeqNum <= 0) {
            this.minSeqNum = seqNum;
            this.firstUnreadSeqNum = seqNum;
        }
        this.elementCount++;

        // force a checkpoint if we wrote checkpointMaxWrites elements since last checkpoint
        // the initial condition of an "empty" checkpoint, maxSeqNum() will return -1
        if (checkpointMaxWrites > 0 && (seqNum >= this.lastCheckpoint.maxSeqNum() + checkpointMaxWrites)) {
            // did we write more than checkpointMaxWrites elements? if so checkpoint now
            checkpoint();
        }
    }

    /**
     * Page is considered empty if it does not contain any element or if all elements are acked.
     *
     * TODO: note that this should be the same as isFullyAcked once fixed per https://github.com/elastic/logstash/issues/7570
     *
     * @return true if the page has no element or if all elements are acked.
     */
    public boolean isEmpty() {
        return this.elementCount == 0 || isFullyAcked();
    }

    public boolean isFullyRead() {
        return unreadCount() <= 0;
//        return this.elementCount <= 0 || this.firstUnreadSeqNum > maxSeqNum();
    }

    public boolean isFullyAcked() {
        final int cardinality = ackedSeqNums.cardinality();
        return elementCount > 0 && cardinality == ackedSeqNums.length()
            && cardinality == elementCount;
    }

    public long unreadCount() {
        return this.elementCount <= 0 ? 0 : Math.max(0, (maxSeqNum() - this.firstUnreadSeqNum) + 1);
    }

    /**
     * update the page acking bitset. trigger checkpoint on the page if it is fully acked or if we acked more than the
     * configured threshold checkpointMaxAcks.
     * note that if the fully acked tail page is the first unacked page, it is not really necessary to also checkpoint
     * the head page to update firstUnackedPageNum because it will be updated in the next upcoming head page checkpoint
     * and in a crash condition, the Queue open recovery will detect and purge fully acked pages
     *
     * @param firstSeqNum Lowest sequence number to ack
     * @param count Number of elements to ack
     * @param checkpointMaxAcks number of acks before forcing a checkpoint
     * @return true if Page and its checkpoint were purged as a result of being fully acked
     * @throws IOException if an IO error occurs
     */
    public boolean ack(long firstSeqNum, int count, int checkpointMaxAcks) throws IOException {
        assert firstSeqNum >= this.minSeqNum :
            String.format("seqNum=%d is smaller than minSeqnum=%d", firstSeqNum, this.minSeqNum);
        final long maxSeqNum = firstSeqNum + count;
        assert maxSeqNum <= this.minSeqNum + this.elementCount :
            String.format(
                "seqNum=%d is greater than minSeqnum=%d + elementCount=%d = %d", maxSeqNum,
                this.minSeqNum, this.elementCount, this.minSeqNum + this.elementCount
            );
        final int offset = Ints.checkedCast(firstSeqNum - this.minSeqNum);
        ackedSeqNums.flip(offset, offset + count);
        // checkpoint if totally acked or we acked more than checkpointMaxAcks elements in this page since last checkpoint
        // note that fully acked pages cleanup is done at queue level in Queue.ack()
        final long firstUnackedSeqNum = firstUnackedSeqNum();

        final boolean done = isFullyAcked();
        if (done) {
            checkpoint();

            // purge fully acked tail page
            if (!this.writable) {
                purge();
                final CheckpointIO cpIO = queue.getCheckpointIO();
                cpIO.purge(cpIO.tailFileName(pageNum));
            }
            assert firstUnackedSeqNum >= this.minSeqNum + this.elementCount - 1:
                    String.format("invalid firstUnackedSeqNum=%d for minSeqNum=%d and elementCount=%d and cardinality=%d", firstUnackedSeqNum, this.minSeqNum, this.elementCount, this.ackedSeqNums.cardinality());

        } else if (checkpointMaxAcks > 0 && firstUnackedSeqNum >= this.lastCheckpoint.getFirstUnackedSeqNum() + checkpointMaxAcks) {
            // did we acked more than checkpointMaxAcks elements? if so checkpoint now
            checkpoint();
        }
        return done;
    }

    public void checkpoint() throws IOException {
        if (this.writable) {
            headPageCheckpoint();
        } else {
            tailPageCheckpoint();
        }
    }

    private void headPageCheckpoint() throws IOException {
        if (this.elementCount > this.lastCheckpoint.getElementCount()) {
            // fsync & checkpoint if data written since last checkpoint

            this.pageIO.ensurePersisted();
            this.forceCheckpoint();
        } else {
            Checkpoint checkpoint = new Checkpoint(this.pageNum, this.queue.firstUnackedPageNum(), this.firstUnackedSeqNum(), this.minSeqNum, this.elementCount);
            if (! checkpoint.equals(this.lastCheckpoint)) {
                // checkpoint only if it changed since last checkpoint

                // non-dry code with forceCheckpoint() to avoid unnecessary extra new Checkpoint object creation
                CheckpointIO io = this.queue.getCheckpointIO();
                io.write(io.headFileName(), checkpoint);
                this.lastCheckpoint = checkpoint;
            }
        }

    }

    public void tailPageCheckpoint() throws IOException {
        // since this is a tail page and no write can happen in this page, there is no point in performing a fsync on this page, just stamp checkpoint
        CheckpointIO io = this.queue.getCheckpointIO();
        this.lastCheckpoint = io.write(io.tailFileName(this.pageNum), this.pageNum, 0, this.firstUnackedSeqNum(), this.minSeqNum, this.elementCount);
    }


    public void ensurePersistedUpto(long seqNum) throws IOException {
        long lastCheckpointUptoSeqNum = this.lastCheckpoint.getMinSeqNum() + this.lastCheckpoint.getElementCount();

        // if the last checkpoint for this headpage already included the given seqNum, no need to fsync/checkpoint
        if (seqNum > lastCheckpointUptoSeqNum) {
            // head page checkpoint does a data file fsync
            checkpoint();
        }
    }

    public void forceCheckpoint() throws IOException {
        Checkpoint checkpoint = new Checkpoint(this.pageNum, this.queue.firstUnackedPageNum(), this.firstUnackedSeqNum(), this.minSeqNum, this.elementCount);
        CheckpointIO io = this.queue.getCheckpointIO();
        io.write(io.headFileName(), checkpoint);
        this.lastCheckpoint = checkpoint;
    }

    public void behead() throws IOException {
        assert this.writable == true : "cannot behead a tail page";

        headPageCheckpoint();

        this.writable = false;
        this.lastCheckpoint = new Checkpoint(0, 0, 0, 0, 0);

        // first thing that must be done after beheading is to create a new checkpoint for that new tail page
        // tail page checkpoint does NOT includes a fsync
        tailPageCheckpoint();
    }

    /**
     * signal that this page is not active and resources can be released
     * @throws IOException if an IO error occurs
     */
    public void deactivate() throws IOException {
        this.getPageIO().deactivate();
    }

    public boolean hasSpace(int byteSize) {
        return this.pageIO.hasSpace(byteSize);
    }

    /**
     * verify if data size plus overhead is not greater than the page capacity
     *
     * @param byteSize the date size to verify
     * @return true if data plus overhead fit in page
     */
    public boolean hasCapacity(int byteSize) {
        return this.pageIO.persistedByteCount(byteSize) <= this.pageIO.getCapacity();
    }

    public void close() throws IOException {
        checkpoint();
        this.pageIO.close();
    }

    public void purge() throws IOException {
        this.pageIO.purge(); // page IO purge calls close
    }

    public int getPageNum() {
        return pageNum;
    }

    public long getMinSeqNum() {
        return this.minSeqNum;
    }

    public int getElementCount() {
        return elementCount;
    }

    public PageIO getPageIO() {
        return pageIO;
    }

    protected long maxSeqNum() {
        return this.minSeqNum + this.elementCount - 1;
    }

    protected long firstUnackedSeqNum() {
        // TODO: eventually refactor to use new bithandling class
        return this.ackedSeqNums.nextClearBit(0) + this.minSeqNum;
    }

}
