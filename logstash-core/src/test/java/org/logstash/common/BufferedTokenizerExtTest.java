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
import org.jruby.RubyEncoding;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.junit.Before;
import org.junit.Test;
import org.logstash.RubyTestBase;
import org.logstash.RubyUtil;

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
    public void shouldNotChangeEncodingOfTokensAfterPartitioning() {
        RubyString rubyString = RubyString.newString(RUBY, new byte[]{(byte) 0xA3, 0x0A, 0x41}); // £ character, newline, A
        IRubyObject rubyInput = rubyString.force_encoding(context, RUBY.newString("ISO8859-1"));
        RubyArray<RubyString> tokens = (RubyArray<RubyString>)sut.extract(context, rubyInput);

        // read the first token, the £ string
        IRubyObject firstToken = tokens.shift(context);
        assertEquals("£", firstToken.toString());

        // verify encoding "ISO8859-1" is preserved in the Java to Ruby String conversion
        RubyEncoding encoding = (RubyEncoding) firstToken.callMethod(context, "encoding");
        assertEquals("ISO-8859-1", encoding.toString());
    }

    @Test
    public void shouldNotChangeEncodingOfTokensAfterPartitioningInCaseMultipleExtractionInInvoked() {
        RubyString rubyString = RubyString.newString(RUBY, new byte[]{(byte) 0xA3}); // £ character
        IRubyObject rubyInput = rubyString.force_encoding(context, RUBY.newString("ISO8859-1"));
        sut.extract(context, rubyInput);
        IRubyObject capitalAInLatin1 = RubyString.newString(RUBY, new byte[]{(byte) 0x41})
                .force_encoding(context, RUBY.newString("ISO8859-1"));
        RubyArray<RubyString> tokens = (RubyArray<RubyString>)sut.extract(context, capitalAInLatin1);
        assertTrue(tokens.isEmpty());

        tokens = (RubyArray<RubyString>)sut.extract(context, RubyString.newString(RUBY, new byte[]{(byte) 0x0A}));

        // read the first token, the £ string
        IRubyObject firstToken = tokens.shift(context);
        assertEquals("£A", firstToken.toString());

        // verify encoding "ISO8859-1" is preserved in the Java to Ruby String conversion
        RubyEncoding encoding = (RubyEncoding) firstToken.callMethod(context, "encoding");
        assertEquals("ISO-8859-1", encoding.toString());
    }

    @Test
    public void shouldNotChangeEncodingOfTokensAfterPartitioningWhenRetrieveLastFlushedToken() {
        RubyString rubyString = RubyString.newString(RUBY, new byte[]{(byte) 0xA3, 0x0A, 0x41}); // £ character, newline, A
        IRubyObject rubyInput = rubyString.force_encoding(context, RUBY.newString("ISO8859-1"));
        RubyArray<RubyString> tokens = (RubyArray<RubyString>)sut.extract(context, rubyInput);

        // read the first token, the £ string
        IRubyObject firstToken = tokens.shift(context);
        assertEquals("£", firstToken.toString());

        // flush and check that the remaining A is still encoded in ISO8859-1
        IRubyObject lastToken = sut.flush(context);
        assertEquals("A", lastToken.toString());

        // verify encoding "ISO8859-1" is preserved in the Java to Ruby String conversion
        RubyEncoding encoding = (RubyEncoding) lastToken.callMethod(context, "encoding");
        assertEquals("ISO-8859-1", encoding.toString());
    }

    @Test
    public void givenDirectFlushInvocationUTF8EncodingIsApplied() {
        RubyString rubyString = RubyString.newString(RUBY, new byte[]{(byte) 0xA3, 0x41}); // £ character, A
        IRubyObject rubyInput = rubyString.force_encoding(context, RUBY.newString("ISO8859-1"));

        // flush and check that the remaining A is still encoded in ISO8859-1
        IRubyObject lastToken = sut.flush(context);
        assertEquals("", lastToken.toString());

        // verify encoding "ISO8859-1" is preserved in the Java to Ruby String conversion
        RubyEncoding encoding = (RubyEncoding) lastToken.callMethod(context, "encoding");
        assertEquals("UTF-8", encoding.toString());
    }
}