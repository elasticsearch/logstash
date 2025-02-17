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


package org.logstash;

import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.RubyTime;
import org.jruby.java.proxies.ConcreteJavaProxy;
import org.junit.Test;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.both;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public final class EventTest extends RubyTestBase {

    @Test
    public void queueableInterfaceRoundTrip() throws Exception {
        Event e = new Event();
        e.setField("foo", 42L);
        e.setField("bar", 42);
        Map<String, Object> inner = new HashMap<>(2);
        inner.put("innerFoo", 42L);
        final RubySymbol symbol = RubyUtil.RUBY.newSymbol("val");
        e.setField("symbol", symbol);
        e.setField("null", null);
        inner.put("innerQuux", 42.42);
        e.setField("baz", inner);
        final BigInteger bigint = BigInteger.valueOf(Long.MAX_VALUE).multiply(BigInteger.TEN);
        final BigDecimal bigdecimal = BigDecimal.valueOf(10L);
        e.setField("biginteger", bigint);
        e.setField("bigdecimal", bigdecimal);
        e.setField("[@metadata][foo]", 42L);
        byte[] binary = e.serialize();
        Event er = Event.deserialize(binary);
        assertEquals(symbol.toString(), er.getField("symbol"));
        assertEquals(bigint, er.getField("biginteger"));
        assertEquals(bigdecimal, er.getField("bigdecimal"));
        assertEquals(42L, er.getField("foo"));
        assertEquals(42L, er.getField("bar"));
        assertEquals(42L, er.getField("[baz][innerFoo]"));
        assertEquals(42.42, er.getField("[baz][innerQuux]"));
        assertEquals(42L, er.getField("[@metadata][foo]"));
        assertNull(er.getField("null"));

        assertEquals(e.getTimestamp().toString(), er.getTimestamp().toString());
    }

    @Test
    public void toBinaryRoundtrip() throws Exception {
        Event e = new Event();
        e.setField("foo", 42L);
        e.setField("bar", 42);
        Map<String, Object> inner = new HashMap<>(2);
        inner.put("innerFoo", 42L);
        inner.put("innerQuux", 42.42);
        e.setField("baz", inner);
        e.setField("[@metadata][foo]", 42L);
        final Timestamp timestamp = new Timestamp();
        e.setField("time", timestamp);
        final Collection<Object> list = new ConvertedList(1);
        list.add("foo");
        e.setField("list", list);
        Event er = Event.deserialize(e.serialize());
        assertEquals(42L, er.getField("foo"));
        assertEquals(42L, er.getField("bar"));
        assertEquals(42L, er.getField("[baz][innerFoo]"));
        assertEquals(42.42, er.getField("[baz][innerQuux]"));
        assertEquals(42L, er.getField("[@metadata][foo]"));
        assertEquals(timestamp, er.getField("time"));
        assertEquals(list, er.getField("list"));
        assertEquals(e.getTimestamp().toString(), er.getTimestamp().toString());
    }

    @Test
    public void toBinaryRoundtripSubstring() throws Exception {
        Event e = new Event();
        e.setField(
            "foo",
            RubyString.newString(RubyUtil.RUBY, "--bar--").substr(RubyUtil.RUBY, 2, 3)
        );
        final RubyString before = (RubyString) e.getUnconvertedField("foo");
        Event er = Event.deserialize(e.serialize());
        assertEquals(before, er.getUnconvertedField("foo"));
    }

    @Test
    public void toBinaryRoundtripNonAscii() throws Exception {
        Event e = new Event();
        e.setField("foo", "bör");
        final RubyString before = (RubyString) e.getUnconvertedField("foo");
        Event er = Event.deserialize(e.serialize());
        assertEquals(before, er.getUnconvertedField("foo"));
        assertTrue(before.op_cmp((RubyString)er.getUnconvertedField("foo")) == 0);
    }

    /**
     * Test for proper BigInteger and BigDecimal serialization
     * related to Jackson/CBOR issue https://github.com/elastic/logstash/issues/8379
     */
    @Test
    public void bigNumsBinaryRoundtrip() throws Exception {
        final Event e = new Event();
        final BigInteger bi = new BigInteger("9223372036854776000");
        final BigDecimal bd =  new BigDecimal("9223372036854776001.99");
        e.setField("bi", bi);
        e.setField("bd", bd);
        final Event deserialized = Event.deserialize(e.serialize());
        assertEquals(bi, deserialized.getField("bi"));
        assertEquals(bd, deserialized.getField("bd"));
    }

    @Test
    public void testBareToJson() throws Exception {
        Event e = new Event();
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testSimpleStringFieldToJson() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("foo", "bar");
        Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":\"bar\",\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testFieldThatIsNotAValidNestedFieldReference() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("this[key]", "value");
        final Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"this[key]\":\"value\",\"@version\":\"1\"}", e.toJson());
    }
    @Test
    public void testFieldThatLooksLikeAValidNestedFieldReference() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("[deeply][nested][field]", "value");
        final Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"[deeply][nested][field]\":\"value\",\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testSimpleIntegerFieldToJson() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("foo", 1);
        Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":1,\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testSimpleLongFieldToJson() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("foo", 1L);
        Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":1,\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testSimpleDecimalFieldToJson() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("foo", 1.0);
        Event e = new Event(data);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":1.0,\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testSimpleMultipleFieldToJson() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("foo", 1.0);
        data.put("bar", "bar");
        data.put("baz", 1);
        Event e = new Event(data);
        assertJsonEquals("{\"bar\":\"bar\",\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":1.0,\"@version\":\"1\",\"baz\":1}", e.toJson());
    }

    @Test
    public void testDeepMapFieldToJson() throws Exception {
        Event e = new Event();
        e.setField("[foo][bar][baz]", 1);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":{\"bar\":{\"baz\":1}},\"@version\":\"1\"}", e.toJson());

        e = new Event();
        e.setField("[foo][0][baz]", 1);
        assertJsonEquals("{\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"foo\":{\"0\":{\"baz\":1}},\"@version\":\"1\"}", e.toJson());
    }

    @Test
    public void testTimestampFieldToJson() throws Exception {
        Event e = new Event();
        final RubyTime time = RubyUtil.RUBY.newTime(1000L);
        e.setField("[foo][bar][baz]", time);
        assertJsonEquals(
            String.format(
                "{\"@timestamp\":\"%s\",\"foo\":{\"bar\":{\"baz\":\"%s\"}},\"@version\":\"1\"}",
                e.getTimestamp().toString(), new Timestamp(time.getDateTime()).toString()
            ), e.toJson()
        );
    }

    @Test
    public void testEventTimestampConstructorStringValueRetainsNanoResolution() {
        final String iso8601TimestampWithNanos = "2023-05-10T21:43:08.726162941Z";
        Event e = new Event(Map.of("@timestamp", iso8601TimestampWithNanos));

        assertEquals("iso8601 string in Event#new(Map) retains precision", e.getEventTimestamp(), Instant.parse(iso8601TimestampWithNanos));
    }

    @Test
    public void testEventTimestampConstructorInstantValueRetainsNanoResolution() {
        final Instant givenInstant = Instant.parse("2023-05-10T21:43:08.726162941Z");
        Event e = new Event(Map.of("@timestamp", givenInstant));

        assertEquals("iso8601 string in Event#new(Map) retains precision", e.getEventTimestamp(), givenInstant);
    }

    @Test
    public void testEventTimestampConstructorZonedDateTimeValueRetainsNanoResolution() {
        final ZonedDateTime zonedDateTime = ZonedDateTime.parse("2023-05-10T21:43:08.726162941Z");
        Event e = new Event(Map.of("@timestamp", zonedDateTime));

        assertEquals("iso8601 string in Event#new(Map) retains precision", e.getEventTimestamp(), zonedDateTime.toInstant());
    }

    @Test
    public void testEventTimestampSetterRetainsNanoResolution() {
        Event e = new Event(Map.of("@timestamp", "2000-01-01T00:00:00.000Z"));

        final Instant updatedTimestamp = Instant.parse("2023-05-10T21:43:08.726162941Z");
        e.setEventTimestamp(updatedTimestamp);

        assertThat(e.getEventTimestamp(), is(equalTo(updatedTimestamp)));
    }

    @Test
    public void testEventTimestampSetterDefaultsToNow() {
        Event e = new Event(Map.of("@timestamp", "2000-01-01T00:00:00.000Z"));

        final Instant baseline = Instant.now();
        e.setEventTimestamp(null);

        final Instant updatedTimestamp = e.getEventTimestamp();
        assertThat(updatedTimestamp, allOf(
                is(notNullValue()),
                both(greaterThanOrEqualTo(baseline)).and(lessThanOrEqualTo(Instant.now()))
        ));

        assertThat("a set-with-null timestamp is actually set", e.getEventTimestamp(), is(equalTo(updatedTimestamp)));
    }

    @Test
    public void testBooleanFieldToJson() throws Exception {
        Event e = new Event();
        e.setField("[foo][bar][baz]", true);
        assertJsonEquals(
            String.format(
                "{\"@timestamp\":\"%s\",\"foo\":{\"bar\":{\"baz\":true}},\"@version\":\"1\"}",
                e.getTimestamp().toString()
            ), e.toJson()
        );
    }

    @Test
    public void testGetFieldList() throws Exception {
        Map<String, Object> data = new HashMap<>();
        List<Object> l = new ArrayList<>();
        data.put("foo", l);
        l.add(1);
        Event e = new Event(data);
        assertEquals(1L, e.getField("[foo][0]"));
    }

    @Test
    public void testDeepGetField() throws Exception {
        Map<String, Object> data = new HashMap<>();
        List<Object> l = new ArrayList<>();
        data.put("foo", l);
        Map<String, Object> m = new HashMap<>();
        m.put("bar", "baz");
        l.add(m);
        Event e = new Event(data);
        assertEquals("baz", e.getField("[foo][0][bar]"));
    }


    @Test
    public void testClone() throws Exception {
        Map<String, Object> data = new HashMap<>();
        List<Object> l = new ArrayList<>();
        data.put("array", l);

        Map<String, Object> m = new HashMap<>();
        m.put("foo", "bar");
        l.add(m);

        data.put("foo", 1.0);
        data.put("bar", "bar");
        data.put("baz", 1);

        Event e = new Event(data);

        Event f = e.clone();

        assertJsonEquals("{\"bar\":\"bar\",\"@timestamp\":\"" + e.getTimestamp().toString() + "\",\"array\":[{\"foo\":\"bar\"}],\"foo\":1.0,\"@version\":\"1\",\"baz\":1}", f.toJson());
        assertJsonEquals(f.toJson(), e.toJson());
    }

    @Test
    public void testToMap() throws Exception {
        Event e = new Event();
        Map<String, Object> original = e.getData();
        Map<String, Object> clone = e.toMap();
        assertFalse(original == clone);
        assertEquals(original, clone);
    }

    @Test
    public void testAppend() throws Exception {
        Map<String, Object> data1 = new HashMap<>();
        data1.put("field1", Arrays.asList("original1", "original2"));

        Map<String, Object> data2 = new HashMap<>();
        data2.put("field1", "original1");

        Event e = new Event(data1);
        Event e2 = new Event(data2);
        e.append(e2);

        assertEquals(2, ((List) e.getField("[field1]")).size());
        assertEquals("original1", e.getField("[field1][0]"));
        assertEquals("original2", e.getField("[field1][1]"));
    }

    @Test
    public void testAppendLists() throws Exception {
        Map<String, Object> data1 = new HashMap<>();
        data1.put("field1", Arrays.asList("original1", "original2"));

        Map<String, Object> data2 = new HashMap<>();
        data2.put("field1", Arrays.asList("original3", "original4"));

        Event e = new Event(data1);
        Event e2 = new Event(data2);
        e.append(e2);

        assertEquals(4, ((List) e.getField("[field1]")).size());
        assertEquals("original1", e.getField("[field1][0]"));
        assertEquals("original2", e.getField("[field1][1]"));
        assertEquals("original3", e.getField("[field1][2]"));
        assertEquals("original4", e.getField("[field1][3]"));
    }

    @Test
    public void testFromJsonWithNull() throws Exception {
        Event[] events = Event.fromJson(null);
        assertEquals(0, events.length);
    }

    @Test
    public void testFromJsonWithEmptyString() throws Exception {
        Event[] events = Event.fromJson("");
        assertEquals(0, events.length);
    }

    @Test
    public void testFromJsonWithBlankString() throws Exception {
        Event[] events = Event.fromJson("   ");
        assertEquals(0, events.length);
    }

    @Test
    public void testFromJsonWithValidJsonMap() throws Exception {
        Event e = Event.fromJson("{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"foo\":\"bar\"}")[0];

        assertEquals("bar", e.getField("[foo]"));
        assertEquals("2015-05-28T23:02:05.350Z", e.getTimestamp().toString());
    }

    @Test
    public void testFromJsonWithValidJsonArrayOfMap() throws Exception {
        Event[] l = Event.fromJson("[{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"foo\":\"bar\"}]");

        assertEquals(1, l.length);
        assertEquals("bar", l[0].getField("[foo]"));
        assertEquals("2015-05-28T23:02:05.350Z", l[0].getTimestamp().toString());

        l = Event.fromJson("[{}]");

        assertEquals(1, l.length);
        assertEquals(null, l[0].getField("[foo]"));

        l = Event.fromJson("[{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"foo\":\"bar\"}, {\"@timestamp\":\"2016-05-28T23:02:05.350Z\",\"foo\":\"baz\"}]");

        assertEquals(2, l.length);
        assertEquals("bar", l[0].getField("[foo]"));
        assertEquals("2015-05-28T23:02:05.350Z", l[0].getTimestamp().toString());
        assertEquals("baz", l[1].getField("[foo]"));
        assertEquals("2016-05-28T23:02:05.350Z", l[1].getTimestamp().toString());
    }

    @Test(expected=IOException.class)
    public void testFromJsonWithInvalidJsonString() throws Exception {
        Event.fromJson("gabeutch");
    }

    @Test(expected=ClassCastException.class)
    public void testFromJsonWithInvalidJsonArray1() throws Exception {
        Event.fromJson("[1,2]");
    }

    @Test(expected=ClassCastException.class)
    public void testFromJsonWithInvalidJsonArray2() throws Exception {
        Event.fromJson("[\"gabeutch\"]");
    }

    @Test(expected=ClassCastException.class)
    public void testFromJsonWithPartialInvalidJsonArray() throws Exception {
        Event.fromJson("[{\"foo\":\"bar\"}, 1]");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testTagOnEmptyTagsField() throws Exception {
        Event e = new Event();
        e.tag("foo");

        List<String> tags = (List<String>)e.getField("tags");
        assertEquals(tags.size(), 1);
        assertEquals(tags.get(0), "foo");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testTagOnExistingTagsField() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("tags", "foo");
        Event e = new Event(data);
        e.tag("bar");

        List<String> tags = (List<String>)e.getField("tags");
        assertEquals(tags.size(), 2);
        assertEquals(tags.get(0), "foo");
        assertEquals(tags.get(1), "bar");
    }

    @Test
    public void toStringWithTimestamp() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("host", "foo");
        data.put("message", "bar");
        Event e = new Event(data);
        assertEquals(e.toString(), e.getTimestamp().toString() + " foo bar");
    }

    @Test
    public void toStringWithoutTimestamp() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("host", "foo");
        data.put("message", "bar");
        Event e = new Event(data);
        e.remove("@timestamp");
        assertEquals(e.toString(), "foo bar");

        e = new Event();
        e.remove("@timestamp");
        assertEquals(e.toString(), "%{host} %{message}");
    }

    @Test
    public void unwrapsJavaProxyValues() throws Exception {
        final Event event = new Event();
        final Timestamp timestamp = new Timestamp();
        event.setField("timestamp", new ConcreteJavaProxy(RubyUtil.RUBY,
            RubyUtil.RUBY_TIMESTAMP_CLASS, timestamp
        ));
        assertThat(event.getField("timestamp"), is(timestamp));
    }

    @SuppressWarnings("rawtypes")
    @Test
    public void metadataFieldsShouldBeValuefied() {
        final Event event = new Event();
        event.setField("[@metadata][foo]", Collections.emptyMap());
        assertEquals(HashMap.class, event.getField("[@metadata][foo]").getClass());

        event.setField("[@metadata][bar]", Collections.singletonList("hello"));
        final List list = (List) event.getField("[@metadata][bar]");
        assertEquals(ArrayList.class, list.getClass());
        assertEquals(list, Arrays.asList("hello"));
    }

    @SuppressWarnings("rawtypes")
    @Test
    public void metadataRootShouldBeValuefied() {
        final Event event = new Event();

        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("foo", Collections.emptyMap());
        metadata.put("bar", Collections.singletonList("hello"));

        event.setField("@metadata", metadata);

        assertEquals(HashMap.class, event.getField("[@metadata][foo]").getClass());

        final List list = (List) event.getField("[@metadata][bar]");
        assertEquals(ArrayList.class, list.getClass());
        assertEquals(list, Arrays.asList("hello"));

    }

    @Test
    public void removeMetadataField() {
        final Event event = new Event();
        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("foo", "bar");
        event.setField("@metadata", metadata);

        final RubyString s = (RubyString)event.remove("[@metadata][foo]");
        assertEquals(s.toString(), "bar");

        assertFalse(event.includes("[@metadata][foo]"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void removeMetadata() {
        final Event event = new Event();
        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("foo", "bar");
        event.setField("@metadata", metadata);

        final Map<String, Object> m = (Map)(event.remove("[@metadata]"));
        assertEquals(m.get("foo"), "bar");

        assertTrue(event.getMetadata().isEmpty());
        assertFalse(event.includes("[@metadata][foo]"));
    }

    @Test(expected = Event.InvalidTagsTypeException.class)
    public void setTagsWithMapShouldThrow() {
        final Event event = new Event();
        event.setField("[tags][foo]", "bar");
    }

    @Test
    public void createEventWithTagsWithMapShouldRename() {
        final Event event = new Event(Map.of("tags", Map.of("poison", "true")));

        assertEquals(event.getField(Event.TAGS), Collections.singletonList(Event.TAGS_FAILURE_TAG));
        assertEquals(event.getField("[_tags][0][poison]"), "true");
    }

    @Test(expected = Event.InvalidTagsTypeException.class)
    public void setTagsWithNumberShouldThrow() {
        final Event event = new Event();
        event.setField("[tags]", 123L);
    }

    @Test
    public void allowTopLevelTagsString() {
        final Event event = new Event();
        event.setField("[tags]", "bar");

        assertNull(event.getField(Event.TAGS_FAILURE));
        assertEquals(event.getField("[tags]"), "bar");
        
        event.setField("[tags]", "foo");
        assertEquals(event.getField("[tags]"), "foo");
    }

    @Test
    public void createEventWithoutTagShouldHaveEmptyTags() {
        final Event event = new Event(Map.of("world", "cup"));
        assertNull(event.getField(Event.TAGS));
        assertNull(event.getField(Event.TAGS_FAILURE));
    }
    
    @Test
    public void allowTopLevelTagsListOfStrings() {
        final Event event = new Event();
        event.setField("[tags]", List.of("foo", "bar"));

        assertNull(event.getField(Event.TAGS_FAILURE));
        assertEquals(event.getField("[tags]"), List.of("foo", "bar"));
    }
}
