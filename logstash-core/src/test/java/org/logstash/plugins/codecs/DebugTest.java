package org.logstash.plugins.codecs;

import org.junit.Test;
import org.logstash.Event;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DebugTest {

    @Test
    public void testEncodeWithoutMetadata() throws IOException {
        Debug encoder = new Debug(new ConfigurationImpl(Collections.emptyMap()), null);
        testEncode(encoder, false);
    }

    @Test
    public void testEncodeWithMetadata() throws IOException {
        Debug encoder = new Debug(new ConfigurationImpl(Collections.singletonMap("metadata", "true")), null);
        testEncode(encoder, true);
    }

    private void testEncode(Debug debug, boolean hasMetadata) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String message = "Hello world";
        String host = "test";
        Event e = new Event();
        e.setField("message", message);
        e.setField("host", host);

        debug.encode(e, outputStream);

        String resultingString = outputStream.toString();
        assertTrue(resultingString.contains(message));
        assertTrue(resultingString.contains(host));
        assertEquals(hasMetadata, resultingString.contains("\"@metadata\" : { }"));
    }

    @Test
    public void testClone() throws IOException  {
        Debug encoder = new Debug(new ConfigurationImpl(Collections.singletonMap("metadata", "true")), null);
        Debug clonedCodec = (Debug) encoder.cloneCodec();
        testEncode(clonedCodec, true);
    }

}
