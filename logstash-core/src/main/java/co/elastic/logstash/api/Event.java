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


package co.elastic.logstash.api;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/**
 * Event interface for Java plugins. Java plugins should not rely on the implementation details of any
 * concrete implementations of the Event interface.
 */
public interface Event {
    Map<String, Object> getData();

    Map<String, Object> getMetadata();

    void cancel();

    void uncancel();

    boolean isCancelled();

    Instant getEventTimestamp();

    void setEventTimestamp(Instant t);

    Object getField(String reference);

    Object getUnconvertedField(String reference);

    void setField(String reference, Object value);

    boolean includes(String field);

    Map<String, Object> toMap();

    Event overwrite(Event e);

    Event append(Event e);

    Object remove(String path);

    String sprintf(String s) throws IOException;

    Event clone();

    String toString();

    void tag(String tag);
}
