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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DecimalStyle;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoField;
import java.util.Date;
import java.util.Locale;
import java.util.Optional;
import java.util.function.UnaryOperator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.logstash.ackedqueue.Queueable;

/**
 * Wrapper around a {@link Instant} with Logstash specific serialization behaviour.
 * This class is immutable and thread-safe since its only state is held in a final {@link Instant}
 * reference and {@link Instant} which itself is immutable and thread-safe.
 */
@JsonSerialize(using = ObjectMappers.TimestampSerializer.class)
@JsonDeserialize(using = ObjectMappers.TimestampDeserializer.class)
public final class Timestamp implements Comparable<Timestamp>, Queueable {

    private static final Logger LOGGER = LogManager.getLogger(Timestamp.class);

    private transient org.joda.time.DateTime time;

    private final Instant instant;

    private static final DateTimeFormatter ISO_INSTANT_MILLIS = new DateTimeFormatterBuilder()
            .appendInstant(3)
            .toFormatter()
            .withResolverStyle(ResolverStyle.STRICT);

    public Timestamp() {
        this(Clock.systemDefaultZone());
    }

    public Timestamp(String iso8601) {
        this(iso8601, Clock.systemDefaultZone(), Locale.getDefault());
    }

    Timestamp(final String iso8601, final Clock clock, final Locale locale) {
        this.instant = tryParse(iso8601, clock, locale);
    }

    Timestamp(final Clock clock) {
        this(clock.instant());
    }

    public Timestamp(long epoch_milliseconds) {
        this(Instant.ofEpochMilli(epoch_milliseconds));
    }

    public Timestamp(final Date date) {
        this(date.toInstant());
    }

    public Timestamp(final org.joda.time.DateTime date) {
        this(date.getMillis());
    }

    public Timestamp(final Instant instant) {
        this.instant = instant;
    }

    /**
     * @deprecated This method returns JodaTime which is deprecated in favor of JDK Instant.
     *   * <p> Use {@link Timestamp#toInstant()} instead. </p>
     */
    @Deprecated
    public org.joda.time.DateTime getTime() {
        if (time == null) {
            time = new org.joda.time.DateTime(instant.toEpochMilli(), org.joda.time.DateTimeZone.UTC);
        }
        return time;
    }

    public Instant toInstant() {
        return instant;
    }

    public static Timestamp now() {
        return new Timestamp();
    }

    public String toString() {
        // ensure minimum precision of 3 decimal places by using our own 3-decimal-place formatter when we have no nanos.
        final DateTimeFormatter formatter = (instant.getNano() == 0 ? ISO_INSTANT_MILLIS : DateTimeFormatter.ISO_INSTANT);
        return formatter.format(instant);
    }

    public long toEpochMilli() {
        return instant.toEpochMilli();
    }

    /**
     * @return the fraction of a second as microseconds from 0 to 999,999; not the number of microseconds since epoch
     */
    public long usec() {
        return instant.getNano() / 1000;
    }

    /**
     * @return the fraction of a second as nanoseconds from 0 to 999,999,999; not the number of nanoseconds since epoch
     */
    public long nsec() {
        return instant.getNano();
    }

    @Override
    public int compareTo(Timestamp other) {
        return instant.compareTo(other.instant);
    }
    
    @Override
    public boolean equals(final Object other) {
        return other instanceof Timestamp && instant.equals(((Timestamp) other).instant);
    }

    @Override
    public int hashCode() {
        return instant.hashCode();
    }

    @Override
    public byte[] serialize() {
        return toString().getBytes();
    }

    // Here we build a DateTimeFormatter that is as forgiving as Joda's ISODateTimeFormat.dateTimeParser()
    // Required yyyy-MM-dd date
    // Optional 'T'-prefixed HH:mm:ss.SSS time (defaults to 00:00:00.000)
    // Optional Zone information, in standard or colons-optional formats (defaults to system zone)
    private static final DateTimeFormatter LENIENT_ISO_DATE_TIME_FORMATTER = (new DateTimeFormatterBuilder())
            .parseCaseInsensitive()
            .append(DateTimeFormatter.ISO_LOCAL_DATE)
            // Time is optional, but if present will begin with a T
            .optionalStart().appendLiteral('T').append(DateTimeFormatter.ISO_LOCAL_TIME).optionalEnd()
            // Timezone is optional, and may land in one of a couple different formats.
            .optionalStart().appendZoneOrOffsetId().optionalEnd()
            .optionalStart().appendOffset("+HHmmss", "Z").optionalEnd()
            .parseDefaulting(ChronoField.HOUR_OF_DAY, 0)
            .parseDefaulting(ChronoField.MINUTE_OF_HOUR, 0)
            .parseDefaulting(ChronoField.SECOND_OF_MINUTE, 0)
            .parseDefaulting(ChronoField.NANO_OF_SECOND, 0)
            .toFormatter()
            .withZone(ZoneId.systemDefault())
            .withDecimalStyle(DecimalStyle.ofDefaultLocale());

    private static Instant tryParse(final String iso8601, final Clock clock, final Locale locale) {
        // be very fast when parsing 2024-12-10T11:03:52.571554Z
        // we do this for writing to the queue
        try {
            int year = Integer.parseInt(iso8601.substring(0, 4));
            int month = Integer.parseInt(iso8601.substring(5, 7));
            int day = Integer.parseInt(iso8601.substring(8, 10));
            int hour = Integer.parseInt(iso8601.substring(11, 13));
            int minute = Integer.parseInt(iso8601.substring(14, 16));
            int second = Integer.parseInt(iso8601.substring(17, 19));
            int nano = Integer.parseInt(iso8601.substring(20, 26)) * 1000;

            return Instant.ofEpochSecond(
                    java.time.LocalDateTime.of(year, month, day, hour, minute, second)
                            .toEpochSecond(java.time.ZoneOffset.UTC),
                    nano);
        } catch (Exception e) {
            LOGGER.trace("Failed optimized ISO8601 parsing for input: {}", iso8601, e);
        }

        final DateTimeFormatter configuredFormatter = LENIENT_ISO_DATE_TIME_FORMATTER.withLocale(locale)
                                                                                     .withDecimalStyle(DecimalStyle.of(locale))
                                                                                     .withZone(clock.getZone());
        return tryParse(iso8601, configuredFormatter)
                .or(() -> tryFallbackParse(iso8601, configuredFormatter, (f) -> f.withDecimalStyle(DecimalStyle.STANDARD)))
                .orElseThrow(() -> new IllegalArgumentException(String.format("Invalid ISO8601 input `%s`", iso8601)));
    }

    private static Optional<Instant> tryParse(final String iso8601,
                                              final DateTimeFormatter configuredFormatter) {
        try {
            return Optional.of(configuredFormatter.parse(iso8601, Instant::from));
        } catch (java.time.format.DateTimeParseException e) {
            LOGGER.trace(String.format("Failed to parse `%s` with locale:`%s` and decimal_style:`%s`", iso8601, configuredFormatter.getLocale(), configuredFormatter.getDecimalStyle()), e);
            return Optional.empty();
        }
    }

    /**
     * Attempts to parse the input if-and-only-if the provided {@code formatterTransformer}
     * effectively transforms the provided {@code baseFormatter}. This is intended to be a
     * fallback method for a maybe-modified formatter to prevent re-parsing the same input
     * with the same formatter multiple times.
     *
     * @param iso8601 an ISO8601-ish string
     * @param baseFormatter the base formatter
     * @param formatterTransformer a transformation operator (such as using DateTimeFormat#withDecimalStyle)
     * @return an {@code Optional}, which contains a value if-and-only-if the effective format is different
     *         from the base format and successfully parsed the input
     */
    private static Optional<Instant> tryFallbackParse(final String iso8601,
                                                      final DateTimeFormatter baseFormatter,
                                                      final UnaryOperator<DateTimeFormatter> formatterTransformer) {
        final DateTimeFormatter modifiedFormatter = formatterTransformer.apply(baseFormatter);
        if (modifiedFormatter.equals(baseFormatter)) { return Optional.empty(); }

        return tryParse(iso8601, modifiedFormatter);
    }
}
