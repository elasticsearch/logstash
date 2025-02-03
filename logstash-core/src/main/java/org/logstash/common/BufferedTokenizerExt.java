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

import org.jruby.*;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.logstash.RubyUtil;

import java.nio.charset.Charset;

@JRubyClass(name = "BufferedTokenizer")
public class BufferedTokenizerExt extends RubyObject {

    private static final long serialVersionUID = 1L;

    private static final RubyString NEW_LINE = (RubyString) RubyUtil.RUBY.newString("\n").
                                                                freeze(RubyUtil.RUBY.getCurrentContext());

    private @SuppressWarnings("rawtypes") RubyArray input = RubyUtil.RUBY.newArray();
    private StringBuilder headToken = new StringBuilder();
    private RubyString delimiter = NEW_LINE;
    private int sizeLimit;
    private boolean hasSizeLimit;
    private int inputSize;
    private boolean bufferFullErrorNotified = false;
    private String encodingName;

    public BufferedTokenizerExt(final Ruby runtime, final RubyClass metaClass) {
        super(runtime, metaClass);
    }

    @JRubyMethod(name = "initialize", optional = 2)
    public IRubyObject init(final ThreadContext context, IRubyObject[] args) {
        if (args.length >= 1) {
            this.delimiter = args[0].convertToString();
        }
        if (args.length == 2) {
            final int sizeLimit = args[1].convertToInteger().getIntValue();
            if (sizeLimit <= 0) {
                throw new IllegalArgumentException("Size limit must be positive");
            }
            this.sizeLimit = sizeLimit;
            this.hasSizeLimit = true;
        }
        this.inputSize = 0;
        return this;
    }

    /**
     * Extract takes an arbitrary string of input data and returns an array of
     * tokenized entities, provided there were any available to extract.  This
     * makes for easy processing of datagrams using a pattern like:
     *
     * {@code tokenizer.extract(data).map { |entity| Decode(entity) }.each do}
     *
     * @param context ThreadContext
     * @param data    IRubyObject
     * @return Extracted tokens
     */
    @JRubyMethod
    @SuppressWarnings("rawtypes")
    public RubyArray extract(final ThreadContext context, IRubyObject data) {
        RubyEncoding encoding = (RubyEncoding) data.convertToString().encoding(context);
        encodingName = encoding.getEncoding().getCharsetName();
        final RubyArray entities = data.convertToString().split(delimiter, -1);
        if (!bufferFullErrorNotified) {
            input.clear();
            input.concat(entities);
        } else {
            // after a full buffer signal
            if (input.isEmpty()) {
                // after a buffer full error, the remaining part of the line, till next delimiter,
                // has to be consumed, unless the input buffer doesn't still contain fragments of
                // subsequent tokens.
                entities.shift(context);
                input.concat(entities);
            } else {
                // merge last of the input with first of incoming data segment
                if (!entities.isEmpty()) {
                    RubyString last = ((RubyString) input.pop(context));
                    RubyString nextFirst = ((RubyString) entities.shift(context));
                    entities.unshift(last.concat(nextFirst));
                    input.concat(entities);
                }
            }
        }

        if (hasSizeLimit) {
            if (bufferFullErrorNotified) {
                bufferFullErrorNotified = false;
                if (input.isEmpty()) {
                    return RubyUtil.RUBY.newArray();
                }
            }
            final int entitiesSize = ((RubyString) input.first()).size();
            if (inputSize + entitiesSize > sizeLimit) {
                bufferFullErrorNotified = true;
                headToken = new StringBuilder();
                inputSize = 0;
                input.shift(context); // consume the token fragment that generates the buffer full
                throw new IllegalStateException("input buffer full");
            }
            this.inputSize = inputSize + entitiesSize;
        }

        if (input.getLength() < 2) {
            // this is a specialization case which avoid adding and removing from input accumulator
            // when it contains just one element
            headToken.append(input.shift(context)); // remove head
            return RubyUtil.RUBY.newArray();
        }

        if (headToken.length() > 0) {
            // if there is a pending token part, merge it with the first token segment present
            // in the accumulator, and clean the pending token part.
            headToken.append(input.shift(context)); // append buffer to first element and
            // create new RubyString with the data specified encoding
            RubyString encodedHeadToken = RubyUtil.RUBY.newString(new ByteList(headToken.toString().getBytes(Charset.forName(encodingName))));
            encodedHeadToken.force_encoding(context, RubyUtil.RUBY.newString(encodingName));
            input.unshift(encodedHeadToken); // reinsert it into the array
            headToken = new StringBuilder();
        }
        headToken.append(input.pop(context)); // put the leftovers in headToken for later
        inputSize = headToken.length();
        return input;
    }

    /**
     * Flush the contents of the input buffer, i.e. return the input buffer even though
     * a token has not yet been encountered
     *
     * @param context ThreadContext
     * @return Buffer contents
     */
    @JRubyMethod
    public IRubyObject flush(final ThreadContext context) {
        final IRubyObject buffer = RubyUtil.toRubyObject(headToken.toString());
        headToken = new StringBuilder();
        inputSize = 0;

        // create new RubyString with the last data specified encoding, if exists
        RubyString encodedHeadToken;
        if (encodingName != null) {
            encodedHeadToken = RubyUtil.RUBY.newString(new ByteList(buffer.toString().getBytes(Charset.forName(encodingName))));
            encodedHeadToken.force_encoding(context, RubyUtil.RUBY.newString(encodingName));
        } else {
            // When used with TCP input it could be that on socket connection the flush method
            // is invoked while no invocation of extract, leaving the encoding name unassigned.
            // In such case also the headToken must be empty
            if (!buffer.toString().isEmpty()) {
                throw new IllegalStateException("invoked flush with unassigned encoding but not empty head token, this shouldn't happen");
            }
            encodedHeadToken = (RubyString) buffer;
        }

        return encodedHeadToken;
    }

    @JRubyMethod(name = "empty?")
    public IRubyObject isEmpty(final ThreadContext context) {
        return RubyUtil.RUBY.newBoolean(headToken.toString().isEmpty() && (inputSize == 0));
    }

}
