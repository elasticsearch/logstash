package org.logstash;

import org.junit.Test;

import static org.junit.Assert.*;

public class FieldReferenceTest {

    @Test
    public void testParseSingleBareField() throws Exception {
        FieldReference f = FieldReference.parse("foo");
        assertEquals(0, f.getPath().length);
        assertEquals(f.getKey(), "foo");
    }

    @Test
    public void testParseSingleFieldPath() throws Exception {
        FieldReference f = FieldReference.parse("[foo]");
        assertEquals(0, f.getPath().length);
        assertEquals(f.getKey(), "foo");
    }

    @Test
    public void testParse2FieldsPath() throws Exception {
        FieldReference f = FieldReference.parse("[foo][bar]");
        assertArrayEquals(f.getPath(), new String[]{"foo"});
        assertEquals(f.getKey(), "bar");
    }

    @Test
    public void testParse3FieldsPath() throws Exception {
        FieldReference f = FieldReference.parse("[foo][bar]]baz]");
        assertArrayEquals(f.getPath(), new String[]{"foo", "bar"});
        assertEquals(f.getKey(), "baz");
    }
}
