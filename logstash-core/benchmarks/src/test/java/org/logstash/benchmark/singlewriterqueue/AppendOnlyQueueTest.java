package org.logstash.benchmark.singlewriterqueue;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.*;

class AppendOnlyQueueTest {

    private static byte[] sampleRandomData;
    private AppendOnlyQueue sut;
    private static Path queuePath;

    @BeforeClass
    public static void beforeAll() throws NoSuchAlgorithmException {
        sampleRandomData = generateRandom(1024);
        queuePath = FileSystems.getDefault().getPath("/tmp/queue");
    }

    @Before
    public void setUp() throws IOException {
        sut = new AppendOnlyQueue("/tmp/queue");
    }

    @After
    public void tearDown() throws IOException {
        sut.close();
        FileUtils.deleteDirectory(queuePath.toFile());
    }

    @Test
    public void testSimpleWriteOnEmptyPage() throws IOException, NoSuchAlgorithmException {
        sut.write(sampleRandomData);

        assertEquals(0, sut.pageNum);
        assertEquals(1024, sut.headBytes);
    }

    private static byte[] generateRandom(int size) throws NoSuchAlgorithmException {
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        final byte[] res = new byte[size];
        random.nextBytes(res);
        return res;
    }

    @Test
    public void testWriteOnPageEdge() throws IOException {
        // almost fill the page
        int loops = (int) (AppendOnlyQueue.PAGE_SIZE / 1024 - 1);
        for (int i = 0; i < loops; i++) {
            sut.write(sampleRandomData);
        }

        // exercise
        sut.write(sampleRandomData);

        assertEquals(0, sut.pageNum);
        assertEquals(AppendOnlyQueue.PAGE_SIZE, sut.headBytes);
    }

    @Test
    public void testWriteOnSecondPageWhenHeadIsFull() throws IOException {
        // almost fill the page
        int loops = (int) (AppendOnlyQueue.PAGE_SIZE / 1024);
        for (int i = 0; i < loops; i++) {
            sut.write(sampleRandomData);
        }

        // exercise
        sut.write(sampleRandomData);

        assertEquals(1, sut.pageNum);
        assertEquals(1024, sut.headBytes);
        final long numPageFiles = Files.list(queuePath).count();
        assertEquals(2, numPageFiles);
    }
}