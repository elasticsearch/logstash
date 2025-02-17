package org.logstash.ackedqueue.io;

import org.junit.Test;
import org.logstash.Event;
import org.logstash.Timestamp;
import org.logstash.ackedqueue.Batch;
import org.logstash.ackedqueue.Queue;
import org.logstash.ackedqueue.Queueable;
import org.logstash.ackedqueue.Settings;
import org.logstash.ackedqueue.SettingsImpl;
import org.logstash.ackedqueue.TestSettings;
import org.logstash.common.Util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipInputStream;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests against old queue binary data
 */
public class QueueBinaryCompatibilityTest {
    @Test
    public void test6_3_0_all_data_types() throws IOException {
        assertAllDataTypesSample("/binary-queue-samples/6.3.0_all_data_types.zip");
    }

    public void assertAllDataTypesSample(String zipFilename) throws IOException {
        Queue queue = binaryQueueSample(zipFilename);
        Batch batch = queue.nonBlockReadBatch(1000);
        Event event = (Event) batch.getElements().get(0);
        assertAllDataTypes(event);
        queue.close();
    }

    public void assertAllDataTypes(Event event) {
        assertThat(event.getField("bigint"), is(equalTo(new BigInteger("99999999999999999999999999999999999"))));
        assertThat(event.getField("int_max"), is(equalTo((long) Integer.MAX_VALUE)));
        assertThat(event.getField("int_min"), is(equalTo((long) Integer.MIN_VALUE)));
        assertThat(event.getField("long_max"), is(equalTo(Long.MAX_VALUE)));
        assertThat(event.getField("long_min"), is(equalTo(Long.MIN_VALUE)));
        assertThat(event.getField("string"), is(equalTo("I am a string!")));
        assertThat(event.getField("utf8_string"), is(equalTo("multibyte-chars-follow-十進数ウェブの国際化慶-and-here-they-end")));
        assertThat(event.getField("boolean"), is(equalTo(false)));
        assertThat(event.getField("timestamp"), is(equalTo(new Timestamp("2018-05-18T17:27:02.397Z"))));

        Map nestedMap = new HashMap<>();
        nestedMap.put("string", "I am a string!");
        assertThat(event.getField("nested_map"), is(equalTo(nestedMap)));

        List mixedArray = Arrays.asList("a", 1L, "b", new Timestamp("2018-05-18T17:27:02.397Z"), true);
        assertThat(event.getField("mixed_array"), is(equalTo(mixedArray)));


        Map complexMapA = new HashMap();
        complexMapA.put("a", 1L);

        Map complexMapB = new HashMap();
        complexMapB.put("b", Arrays.asList("a string", 2L));

        Map complexMapXYZ = new HashMap();
        complexMapXYZ.put("x", "y");
        complexMapXYZ.put("z", true);
        Map complexMapC = new HashMap();
        complexMapC.put("c", Arrays.asList(complexMapXYZ));


        List complex = Arrays.asList(complexMapA, complexMapB, complexMapC);
        assertThat(event.getField("complex"), is(equalTo(complex)));

    }

    Queue binaryQueueSample(String resourcePath) throws IOException {
        Path queueDir = unpackBinarySample(resourcePath);
        Settings settings = sampleSettings(queueDir, 1024*1024*250);
        Queue queue =  new Queue(settings);
        queue.open();
        return queue;
    }

    Settings sampleSettings(Path queueDir, int pageCapacity) {
        return SettingsImpl.fileSettingsBuilder(queueDir.toString()).capacity(pageCapacity)
            .checkpointMaxWrites(1).elementClass(Event.class).build();
    }

    Path unpackBinarySample(String resourcePath) throws IOException {
        InputStream is = QueueBinaryCompatibilityTest.class.getResourceAsStream(resourcePath);
        assert(is != null);
        ZipInputStream zis = new ZipInputStream(is);
        Path destination = Files.createTempDirectory("temp");
        Util.unzipToDirectory(zis, destination, true);
        return destination;
    }
}
