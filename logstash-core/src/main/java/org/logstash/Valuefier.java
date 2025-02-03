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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.joda.time.DateTime;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyFloat;
import org.jruby.RubyHash;
import org.jruby.RubyNil;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.RubyTime;
import org.jruby.ext.bigdecimal.RubyBigDecimal;
import org.jruby.java.proxies.ArrayJavaProxy;
import org.jruby.java.proxies.ConcreteJavaProxy;
import org.jruby.java.proxies.JavaProxy;
import org.jruby.java.proxies.MapJavaProxy;
import org.jruby.javasupport.JavaUtil;
import org.jruby.runtime.builtin.IRubyObject;
import org.logstash.ext.JrubyTimestampExtLibrary;

public final class Valuefier {

    public static final Valuefier.Converter IDENTITY = input -> input;

    private static final Valuefier.Converter FLOAT_CONVERTER =
        input -> RubyUtil.RUBY.newFloat(((Number) input).doubleValue());

    private static final Valuefier.Converter LONG_CONVERTER
        = input -> RubyUtil.RUBY.newFixnum(((Number) input).longValue());

    /**
     * Unwraps a {@link JavaProxy} and passes the result to {@link Valuefier#convert(Object)}.
     * Handles {code IRubyObject[]} as a special case, since we do only receive this type wrapped
     * in a {@link JavaProxy} and never directly as an argument to
     * {@link Valuefier#convert(Object)}.
     */
    private static final Valuefier.Converter JAVAPROXY_CONVERTER =
        input -> {
            final Object obj = JavaUtil.unwrapJavaObject((JavaProxy) input);
            if (obj instanceof IRubyObject[]) {
                return ConvertedList.newFromRubyArray((IRubyObject[]) obj);
            }
            try {
                return Valuefier.convert(obj);
            } catch (IllegalArgumentException e) {
                final Class<?> cls = obj.getClass();
                throw new IllegalArgumentException(String.format(
                    "Missing Valuefier handling for full class name=%s, simple name=%s, wrapped object=%s",
                    cls.getName(), cls.getSimpleName(), obj.getClass().getName()
                ), e);
            }
        };

    private static final Map<Class<?>, Valuefier.Converter> CONVERTER_MAP = initConverters();

    private Valuefier() {
    }

    public static Object convert(final Object o) {
        if (o == null) {
            return RubyUtil.RUBY.getNil();
        }
        final Class<?> cls = o.getClass();
        final Valuefier.Converter converter = CONVERTER_MAP.get(cls);
        if (converter != null) {
            return converter.convert(o);
        }
        return fallbackConvert(o, cls);
    }

    /**
     * Fallback for types not covered by {@link Valuefier#convert(Object)} as a result of no
     * {@link Valuefier.Converter} having been cached for the given class. Uses the fact that
     * the only subclasses of the keys in {@link Valuefier#CONVERTER_MAP} as set up by
     * {@link Valuefier#initConverters()} can be converted here and hence find the appropriate
     * super class for unknown types by checking each entry in {@link Valuefier#CONVERTER_MAP} for
     * being a supertype of the given class.
     * @param o Object to convert
     * @param cls Class of given object {@code o}
     * @return Conversion result equivalent to what {@link Valuefier#convert(Object)} would return
     */
    private static Object fallbackConvert(final Object o, final Class<?> cls) {
        for (final Map.Entry<Class<?>, Valuefier.Converter> entry : CONVERTER_MAP.entrySet()) {
            if (entry.getKey().isAssignableFrom(cls)) {
                final Valuefier.Converter found = entry.getValue();
                CONVERTER_MAP.put(cls, found);
                return found.convert(o);
            }
        }
        throw new MissingConverterException(cls);
    }

    @SuppressWarnings("unchecked")
    private static Map<Class<?>, Valuefier.Converter> initConverters() {
        final Map<Class<?>, Valuefier.Converter> converters =
            new ConcurrentHashMap<>(50, 0.2F, 1);
        converters.put(RubyString.class, IDENTITY);
        converters.put(RubyNil.class, IDENTITY);
        converters.put(RubySymbol.class, IDENTITY);
        converters.put(RubyFixnum.class, IDENTITY);
        converters.put(JrubyTimestampExtLibrary.RubyTimestamp.class, IDENTITY);
        converters.put(RubyFloat.class, IDENTITY);
        converters.put(ConvertedMap.class, IDENTITY);
        converters.put(ConvertedList.class, IDENTITY);
        converters.put(RubyBoolean.class, IDENTITY);
        converters.put(RubyBignum.class, IDENTITY);
        converters.put(RubyBigDecimal.class, IDENTITY);
        converters.put(String.class, input -> RubyUtil.RUBY.newString((String) input));
        converters.put(Byte.class, input -> RubyUtil.RUBY.newString(input.toString()));
        converters.put(Short.class, LONG_CONVERTER);
        converters.put(Float.class, FLOAT_CONVERTER);
        converters.put(Double.class, FLOAT_CONVERTER);
        converters.put(
            BigInteger.class, value -> RubyBignum.newBignum(RubyUtil.RUBY, (BigInteger) value)
        );
        converters.put(
            BigDecimal.class, value -> new RubyBigDecimal(RubyUtil.RUBY, (BigDecimal) value)
        );
        converters.put(Long.class, LONG_CONVERTER);
        converters.put(Integer.class, LONG_CONVERTER);
        converters.put(Short.class, LONG_CONVERTER);
        converters.put(Byte.class, LONG_CONVERTER);
        converters.put(Boolean.class, input -> RubyUtil.RUBY.newBoolean((Boolean) input));
        converters.put(
            Timestamp.class,
            input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                RubyUtil.RUBY, (Timestamp) input
            )
        );
        converters.put(
            RubyTime.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                RubyUtil.RUBY, new Timestamp(((RubyTime) input).toInstant())
            )
        );
        converters.put(
            DateTime.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                RubyUtil.RUBY, new Timestamp((DateTime) input)
            )
        );
        converters.put(
                Date.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                RubyUtil.RUBY, new Timestamp((Date) input)
            )
        );
        converters.put(RubyHash.class, input -> ConvertedMap.newFromRubyHash((RubyHash) input));
        converters.put(Map.class, input -> ConvertedMap.newFromMap((Map<String, Object>) input));
        converters.put(List.class, input -> ConvertedList.newFromList((List) input));
        converters.put(ArrayJavaProxy.class, JAVAPROXY_CONVERTER);
        converters.put(ConcreteJavaProxy.class, JAVAPROXY_CONVERTER);
        converters.put(
            MapJavaProxy.class,
            input -> ConvertedMap.newFromMap(
                (Map<String, Object>) ((MapJavaProxy) input).getObject()
            )
        );
        converters.put(
            RubyArray.class, input -> ConvertedList.newFromRubyArray((RubyArray) input)
        );
        converters.put(
                LocalDate.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                        RubyUtil.RUBY, new Timestamp(((LocalDate) input).atStartOfDay().toInstant(ZoneOffset.UTC))
                )
        );
        converters.put(
                LocalDateTime.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                        RubyUtil.RUBY, new Timestamp(((LocalDateTime) input).toInstant(ZoneOffset.UTC))
                )
        );
        converters.put(
                ZonedDateTime.class, input -> JrubyTimestampExtLibrary.RubyTimestamp.newRubyTimestamp(
                        RubyUtil.RUBY, new Timestamp(((ZonedDateTime) input).toInstant())
                )
        );
        return converters;
    }

    public interface Converter {

        Object convert(Object input);
    }
}
