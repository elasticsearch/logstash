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

package org.logstash.common;

import org.jruby.RubyArray;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.junit.Before;
import org.junit.Test;
import org.logstash.RubyTestBase;
import org.logstash.RubyUtil;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.logstash.RubyUtil.RUBY;

@SuppressWarnings("unchecked")
public final class BufferedTokenizerExtTest extends RubyTestBase {

    private BufferedTokenizerExt sut;
    private ThreadContext context;

    @Before
    public void setUp() {
        sut = new BufferedTokenizerExt(RubyUtil.RUBY, RubyUtil.BUFFERED_TOKENIZER);
        context = RUBY.getCurrentContext();
        IRubyObject[] args = {};
        sut.init(context, args);
    }

    @Test
    public void shouldTokenizeASingleToken() {
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("foo\n"));

        assertEquals(List.of("foo"), tokens);
    }

    @Test
    public void shouldMergeMultipleToken() {
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("foo"));
        assertTrue(tokens.isEmpty());

        tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("bar\n"));
        assertEquals(List.of("foobar"), tokens);
    }

    @Test
    public void shouldTokenizeMultipleToken() {
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("foo\nbar\n"));

        assertEquals(List.of("foo", "bar"), tokens);
    }

    @Test
    public void shouldIgnoreEmptyPayload() {
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString(""));
        assertTrue(tokens.isEmpty());

        tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("foo\nbar"));
        assertEquals(List.of("foo"), tokens);
    }

    @Test
    public void shouldTokenizeEmptyPayloadWithNewline() {
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("\n"));
        assertEquals(List.of(""), tokens);

        tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("\n\n\n"));
        assertEquals(List.of("", "", ""), tokens);
    }

    @Test
    public void shouldRespectTheCharset() {
        final String input = new String(new byte[] {(byte) 0xA3}, StandardCharsets.ISO_8859_1);
        sut.extract(context, RubyUtil.RUBY.newString(input));

        // send a delimiter to trigger the output of the only token
        RubyArray<RubyString> tokens = (RubyArray<RubyString>) sut.extract(context, RubyUtil.RUBY.newString("\n"));

        String token = (String) tokens.iterator().next();
        assertEquals("£", token);
        assertEqualsBytes(new byte[] {(byte) 0xC2, (byte) 0xA3}, token.getBytes(StandardCharsets.UTF_8));
        assertEqualsBytes(new byte[] {(byte) 0xA3}, token.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void assertEqualsBytes(byte[] expected, byte[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], actual[i]);
        }
    }

    @Test
    public void testEncodingIsPreserved() {
        RubyString rubyString = RubyString.newString(RUBY, new byte[]{(byte) 0xA3});

        IRubyObject rubyInput = rubyString.force_encoding(context, RUBY.newString("ISO8859-1"));
        sut.extract(context, rubyInput);

        assertEqualsBytes(new byte[]{(byte) 0xA3}, ((RubyString) sut.flush(context)).getBytes());
    }
}