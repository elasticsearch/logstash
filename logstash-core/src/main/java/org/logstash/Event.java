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

import co.elastic.logstash.api.EventFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.jruby.RubyNil;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.logstash.ackedqueue.Queueable;
import org.logstash.ext.JrubyTimestampExtLibrary;
import org.logstash.plugins.BasicEventFactory;

import java.io.IOException;
import java.io.Serializable;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.logstash.ObjectMappers.CBOR_MAPPER;
import static org.logstash.ObjectMappers.JSON_MAPPER;

/**
 * Event implementation, is the Logstash's event implementation
 * */
public final class Event implements Cloneable, Queueable, co.elastic.logstash.api.Event {

    private boolean cancelled;
    private ConvertedMap data;
    private ConvertedMap metadata;

    public static final String METADATA = "@metadata";
    public static final String METADATA_BRACKETS = "[" + METADATA + "]";
    public static final String TIMESTAMP = "@timestamp";
    public static final String TIMESTAMP_FAILURE_TAG = "_timestampparsefailure";
    public static final String TIMESTAMP_FAILURE_FIELD = "_@timestamp";
    public static final String VERSION = "@version";
    public static final String VERSION_ONE = "1";
    private static final String DATA_MAP_KEY = "DATA";
    private static final String META_MAP_KEY = "META";
    public static final String TAGS = "tags";
    public static final String TAGS_FAILURE_TAG = "_tagsparsefailure";
    public static final String TAGS_FAILURE = "_tags";

    private static final FieldReference TAGS_FIELD = FieldReference.from(TAGS);
    private static final FieldReference TAGS_FAILURE_FIELD = FieldReference.from(TAGS_FAILURE);

    private static final Logger logger = LogManager.getLogger(Event.class);

    public Event()
    {
        this.metadata = new ConvertedMap(10);
        this.data = new ConvertedMap(10);
        this.data.putInterned(VERSION, VERSION_ONE);
        this.cancelled = false;
        setTimestamp(Timestamp.now());
    }

    /**
     * Constructor from a map that will be copied and the copy will have its contents converted to
     * Java objects.
     * @param data Map that is assumed to have either {@link String} or {@link RubyString}
     * keys and may contain Java and Ruby objects.
     */
    public Event(final Map<? extends Serializable, Object> data) {
        this(ConvertedMap.newFromMap(data));
    }

    /**
     * Constructor wrapping a {@link ConvertedMap} without copying it. Any changes this instance
     * makes to its underlying data will be propagated to it.
     * @param data Converted Map
     */
    @SuppressWarnings("unchecked")
    public Event(ConvertedMap data) {
        this.data = data;
        if (!this.data.containsKey(VERSION)) {
            this.data.putInterned(VERSION, VERSION_ONE);
        }

        if (this.data.containsKey(METADATA)) {
            this.metadata =
                ConvertedMap.newFromMap((Map<String, Object>) this.data.remove(METADATA));
        } else {
            this.metadata = new ConvertedMap(10);
        }
        this.cancelled = false;

        // guard tags field from key/value map, only string or list is allowed
        final Object tags = Accessors.get(data, TAGS_FIELD);
        if (!isLegalTagValue(tags)) {
            initFailTag(tags);
            initTag(TAGS_FAILURE_TAG);
        }

        Object providedTimestamp = data.get(TIMESTAMP);
        // keep reference to the parsedTimestamp for tagging below
        Timestamp parsedTimestamp = initTimestamp(providedTimestamp);
        setTimestamp(parsedTimestamp == null ? Timestamp.now() : parsedTimestamp);
        // the tag() method has to be called after the Accessors initialization
        if (parsedTimestamp == null) {
            tag(TIMESTAMP_FAILURE_TAG);
            this.setField(TIMESTAMP_FAILURE_FIELD, providedTimestamp);
        }
    }

    @Override
    public ConvertedMap getData() {
        return this.data;
    }

    @Override
    public ConvertedMap getMetadata() {
        return this.metadata;
    }

    @Override
    public void cancel() {
        this.cancelled = true;
    }

    @Override
    public void uncancel() {
        this.cancelled = false;
    }

    @Override
    public boolean isCancelled() {
        return this.cancelled;
    }

    @Override
    public Instant getEventTimestamp() {
        Timestamp t = getTimestamp();
        return (t != null)
                ? t.toInstant()
                : null;
    }

    @Override
    public void setEventTimestamp(final Instant timestamp) {
        setTimestamp(timestamp != null
                ? new Timestamp(timestamp)
                : new Timestamp(Instant.now()));
    }

    public Timestamp getTimestamp() {
        final JrubyTimestampExtLibrary.RubyTimestamp timestamp = 
            (JrubyTimestampExtLibrary.RubyTimestamp) data.get(TIMESTAMP);
        return (timestamp != null)
                ? timestamp.getTimestamp()
                : null;
    }

    public void setTimestamp(Timestamp t) {
        this.data.putInterned(
            TIMESTAMP, JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(RubyUtil.RUBY, t)
        );
    }

    @Override
    public Object getField(final String reference) {
        final Object unconverted = getUnconvertedField(FieldReference.from(reference));
        return unconverted == null ? null : Javafier.deep(unconverted);
    }

    @Override
    public Object getUnconvertedField(final String reference) {
        return getUnconvertedField(FieldReference.from(reference));
    }

    public Object getUnconvertedField(final FieldReference field) {
        switch (field.type()) {
            case FieldReference.META_PARENT:
                return this.metadata;
            case FieldReference.META_CHILD:
                return Accessors.get(metadata, field);
            default:
                return Accessors.get(data, field);
        }
    }

    @Override
    public void setField(final String reference, final Object value) {
        setField(FieldReference.from(reference), value);
    }

    @SuppressWarnings("unchecked")
    public void setField(final FieldReference field, final Object value) {
        if ((field.equals(TAGS_FIELD) && !isLegalTagValue(value)) || isTagsWithMap(field)) {
            throw new InvalidTagsTypeException(field, value);
        }

        switch (field.type()) {
            case FieldReference.META_PARENT:
                // ConvertedMap.newFromMap already does valuefication
                this.metadata = ConvertedMap.newFromMap((Map<String, Object>) value);
                break;
            case FieldReference.META_CHILD:
                Accessors.set(metadata, field, Valuefier.convert(value));
                break;
            default:
                Accessors.set(data, field, Valuefier.convert(value));
        }
    }

    private boolean isTagsWithMap(final FieldReference field) {
        return field.getPath() != null && field.getPath().length > 0 && field.getPath()[0].equals(TAGS);
    }

    private boolean isLegalTagValue(final Object value) {
        if (value instanceof String || value instanceof RubyString || value == null) {
            return true;
        } else if (value instanceof List) {
            for (Object item: (List) value) {
                if (!(item instanceof String) && !(item instanceof RubyString)) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    @Override
    public boolean includes(final String field) {
        return includes(FieldReference.from(field));
    }

    public boolean includes(final FieldReference field) {
        switch (field.type()) {
            case FieldReference.META_PARENT:
                return true;
            case FieldReference.META_CHILD:
                return Accessors.includes(metadata, field);
            default:
                return Accessors.includes(data, field);
        }
    }

    private static Event fromSerializableMap(final byte[] source) throws IOException {
        final Map<String, Map<String, Object>> representation =
            CBOR_MAPPER.readValue(source, ObjectMappers.EVENT_MAP_TYPE);
        if (representation == null) {
            throw new IOException("incompatible from binary object type only HashMap is supported");
        }
        final Map<String, Object> dataMap = representation.get(DATA_MAP_KEY);
        if (dataMap == null) {
            throw new IOException("The deserialized Map must contain the \"DATA\" key");
        }
        final Map<String, Object> metaMap = representation.get(META_MAP_KEY);
        if (metaMap == null) {
            throw new IOException("The deserialized Map must contain the \"META\" key");
        }
        dataMap.put(METADATA, metaMap);
        return new Event(dataMap);
    }

    public String toJson() throws JsonProcessingException {
        return JSON_MAPPER.writeValueAsString(this.data);
    }

    private static final Event[] NULL_ARRAY = new Event[0];

    @SuppressWarnings("unchecked")
    private static Object parseJson(final String json) throws IOException {
        return JSON_MAPPER.readValue(json, Object.class);
    }

    /**
     * Map a JSON string into events.
     * @param json input string
     * @return events
     * @throws IOException when (JSON) parsing fails
     */
    public static Event[] fromJson(final String json) throws IOException {
        return fromJson(json, BasicEventFactory.INSTANCE);
    }

    /**
     * Map a JSON string into events.
     * @param json input string
     * @param factory event factory
     * @return events
     * @throws IOException when (JSON) parsing fails
     */
    @SuppressWarnings("unchecked")
    public static Event[] fromJson(final String json, final EventFactory factory) throws IOException {
        // empty/blank json string does not generate an event
        if (json == null || isBlank(json)) {
            return NULL_ARRAY;
        }

        Object o = parseJson(json);
        // we currently only support Map or Array json objects
        if (o instanceof Map) {
            // NOTE: we need to assume the factory returns org.logstash.Event impl
            return new Event[] { (Event) factory.newEvent((Map<? extends Serializable, Object>) o) };
        }
        if (o instanceof List) { // Jackson returns an ArrayList
            return fromList((List<Map<String, Object>>) o, factory);
        }

        throw new IOException("incompatible json object type=" + o.getClass().getName() + " , only hash map or arrays are supported");
    }

    private static Event[] fromList(final List<Map<String, Object>> list, final EventFactory factory) {
        final int len = list.size();
        Event[] result = new Event[len];
        for (int i = 0; i < len; i++) {
            result[i] = (Event) factory.newEvent(list.get(i));
        }
        return result;
    }

    @Override
    public Map<String, Object> toMap() {
        return Cloner.deep(this.data);
    }

    @Override
    public co.elastic.logstash.api.Event overwrite(co.elastic.logstash.api.Event e) {
        if (e instanceof Event) {
            return overwrite((Event)e);
        }
        return e;
    }

    @Override
    public co.elastic.logstash.api.Event append(co.elastic.logstash.api.Event e) {
        if (e instanceof Event) {
            return append((Event)e);
        }
        return e;
    }

    public Event overwrite(Event e) {
        this.data = e.data;
        this.cancelled = e.cancelled;
        Timestamp t = e.getTimestamp();
        setTimestamp(t == null ? new Timestamp() : t);
        return this;
    }

    public Event append(Event e) {
        Util.mapMerge(this.data, e.data);

        return this;
    }

    @Override
    public Object remove(final String path) {
        return remove(FieldReference.from(path));
    }

    public Object remove(final FieldReference field) {
        switch (field.type()) {
            case FieldReference.META_PARENT:
                // removal of metadata is actually emptying metadata.
                final ConvertedMap old_value =  ConvertedMap.newFromMap(this.metadata);
                this.metadata = new ConvertedMap();
                return Javafier.deep(old_value);
            case FieldReference.META_CHILD:
                return Accessors.del(metadata, field);
            default:
                return Accessors.del(data, field);
        }
    }

    @Override
    public String sprintf(String s) throws IOException {
        return StringInterpolation.evaluate(this, s);
    }

    @Override
    public Event clone() {
        final ConvertedMap map =
            ConvertedMap.newFromMap(Cloner.<Map<String, Object>>deep(data));
        map.putInterned(METADATA, Cloner.<Map<String, Object>>deep(metadata));
        return new Event(map);
    }

    @Override
    public String toString() {
        Object hostField = this.getField("host");
        Object messageField = this.getField("message");
        String hostMessageString = (hostField != null ? hostField.toString() : "%{host}") + " " + (messageField != null ? messageField.toString() : "%{message}");

        Timestamp t = getTimestamp();
        return t != null
                ? t.toString() + " " + hostMessageString
                : hostMessageString;
    }

    private static boolean isBlank(final String str) {
        final int len = str.length();
        if (len == 0) return true;
        for (int i = 0; i < len; i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static Timestamp initTimestamp(Object o) {
        if (o == null || o instanceof RubyNil) {
            // most frequent
            return new Timestamp();
        } else {
            return parseTimestamp(o);
        }
    }

    /**
     * Cold path of {@link Event#initTimestamp(Object)}.
     * @param o Object to parse Timestamp out of
     * @return Parsed {@link Timestamp} or {@code null} on failure
     */
    private static Timestamp parseTimestamp(final Object o) {
        try {
            if (o instanceof String) {
                // second most frequent
                return new Timestamp((String) o);
            } else if (o instanceof RubyString) {
                return new Timestamp(o.toString());
            } else if (o instanceof JrubyTimestampExtLibrary.RubyTimestamp) {
                return ((JrubyTimestampExtLibrary.RubyTimestamp) o).getTimestamp();
            } else if (o instanceof Timestamp) {
                return (Timestamp) o;
            } else if (o instanceof Instant) {
                return new Timestamp((Instant) o);
            } else if (o instanceof ZonedDateTime) {
                return new Timestamp(((ZonedDateTime) o).toInstant());
            } else if (o instanceof DateTime) {
                return new Timestamp((DateTime) o);
            } else if (o instanceof Date) {
                return new Timestamp((Date) o);
            } else if (o instanceof RubySymbol) {
                return new Timestamp(((RubySymbol) o).asJavaString());
            } else {
                logger.warn("Unrecognized " + TIMESTAMP + " value type=" + o.getClass().toString());
            }
        } catch (IllegalArgumentException e) {
            logger.warn("Error parsing " + TIMESTAMP + " string value=" + o.toString());
        }
        return null;
    }

    @Override
    public void tag(final String tag) {
        final Object tags = Accessors.get(data, TAGS_FIELD);
        // short circuit the null case where we know we won't need deduplication step below at the end
        if (tags == null) {
            initTag(tag);
        } else {
            existingTag(Javafier.deep(tags), tag);
        }
    }

    /**
     * Branch of {@link Event#tag(String)} that handles adding the first tag to this event.
     * @param tag Tag to add
     */
    private void initTag(final String tag) {
        final ConvertedList list = new ConvertedList(1);
        list.add(RubyUtil.RUBY.newString(tag));
        Accessors.set(data, TAGS_FIELD, list);
    }

    /**
     * Branch of {@link Event#tag(String)} that handles adding to existing tags.
     * @param tags Existing Tag(s)
     * @param tag Tag to add
     */
    @SuppressWarnings("unchecked")
    private void existingTag(final Object tags, final String tag) {
        if (tags instanceof List) {
            appendTag((List<String>) tags, tag);
        } else {
            scalarTagFallback((String) tags, tag);
        }
    }

    /**
     * Merge the given tag into the given list of existing tags if the list doesn't already contain
     * the tag.
     * @param tags Existing tag list
     * @param tag Tag to add
     */
    private void appendTag(final List<String> tags, final String tag) {
        // TODO: we should eventually look into using alternate data structures to do more efficient dedup but that will require properly defining the tagging API too
        if (!tags.contains(tag)) {
            tags.add(tag);
            Accessors.set(data, TAGS_FIELD, ConvertedList.newFromList(tags));
        }
    }

    private void initFailTag(final Object tag) {
        final ConvertedList list = new ConvertedList(1);
        list.add(tag);
        Accessors.set(data, TAGS_FAILURE_FIELD, list);
    }

    /**
     * Fallback for {@link Event#tag(String)} in case "tags" was populated by just a String value
     * and needs to be converted to a list before appending to it.
     * @param existing Existing Tag
     * @param tag Tag to add
     */
    private void scalarTagFallback(final String existing, final String tag) {
        final List<String> tags = new ArrayList<>(2);
        tags.add(existing);
        appendTag(tags, tag);
    }

    @Override
    public byte[] serialize() throws JsonProcessingException {
        final Map<String, Map<String, Object>> map = new HashMap<>(2, 1.0F);
        map.put(DATA_MAP_KEY, this.data);
        map.put(META_MAP_KEY, this.metadata);
        return CBOR_MAPPER.writeValueAsBytes(map);
    }

    public static Event deserialize(byte[] data) throws IOException {
        if (data == null || data.length == 0) {
            return new Event();
        }
        return fromSerializableMap(data);
    }

    public static class InvalidTagsTypeException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public InvalidTagsTypeException(final FieldReference field, final Object value) {
            super(String.format("Could not set the reserved tags field '%s' to value '%s'. " +
                            "The tags field only accepts string or array of string.",
                    getCanonicalFieldReference(field), value
            ));
        }

        private static String getCanonicalFieldReference(final FieldReference field) {
            List<String> path = new ArrayList<>(List.of(field.getPath()));
            path.add(field.getKey());
            return path.stream().collect(Collectors.joining("][", "[", "]"));
        }
    }
}
