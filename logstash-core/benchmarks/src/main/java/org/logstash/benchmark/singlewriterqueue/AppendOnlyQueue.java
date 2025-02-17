package org.logstash.benchmark.singlewriterqueue;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Path;

/**
 * Not thread-safe, it thought to measure single thread writing segmented (64Mb) files on disk
 */
public class AppendOnlyQueue {

    private final Path dirPath;
    private File head;
    int headBytes = 0;
    int pageNum = 0;
    static final long PAGE_SIZE = 64 * 1024 * 1024;
    private MappedByteBuffer buffer;

    public AppendOnlyQueue(String path) throws IOException {
        this.dirPath = FileSystems.getDefault().getPath(path);
        this.head = dirPath.resolve("page." + pageNum).toFile();
        mapFile();
    }

    // NB data is supposed to be 1/2/4/8 Kb
    public void write(byte[] data) throws IOException {
        if (headBytes < PAGE_SIZE) {
            buffer.put(data);
            headBytes += data.length;
        } else {
            this.buffer.force(); //TODO unclean like in Logstash?
            pageNum ++;
            this.head = dirPath.resolve("page." + pageNum).toFile();
            mapFile();
            buffer.put(data);
            headBytes = data.length;
//            System.out.println("switched page file counter to: " + pageNum);
        }
    }

    // memory map data file to this.buffer and read initial version byte
    private void mapFile() throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(this.head, "rw")) {
            this.buffer = raf.getChannel().map(FileChannel.MapMode.READ_WRITE, 0, PAGE_SIZE);
        }
        this.buffer.load();
        this.buffer.position(0);
    }

    public void close() {
        this.buffer.force();
    }
}