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

package org.logstash.util;

import org.junit.Test;

import org.logstash.RubyTestBase;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;

public class CloudSettingAuthTest extends RubyTestBase {

    @Test
    public void testThrowExceptionWhenGivenStringWithoutSeparatorOrPassword() {
        Exception thrownException = assertThrows(org.jruby.exceptions.ArgumentError.class, () -> {
            new CloudSettingAuth("foobarbaz");
        });
        assertThat(thrownException.getMessage(), containsString("Cloud Auth username and password format should be"));
    }

    @Test
    public void testThrowExceptionWhenGivenStringWithoutPassword() {
        Exception thrownException = assertThrows(org.jruby.exceptions.ArgumentError.class, () -> {
            new CloudSettingAuth("foo:");
        });
        assertThat(thrownException.getMessage(), containsString("Cloud Auth username and password format should be"));
    }

    @Test
    public void testThrowExceptionWhenGivenStringWithoutUsername() {
        Exception thrownException = assertThrows(org.jruby.exceptions.ArgumentError.class, () -> {
            new CloudSettingAuth(":bar");
        });
        assertThat(thrownException.getMessage(), containsString("Cloud Auth username and password format should be"));
    }

    @Test
    public void testThrowExceptionWhenGivenStringWhichIsEmpty() {
        Exception thrownException = assertThrows(org.jruby.exceptions.ArgumentError.class, () -> {
            new CloudSettingAuth("");
        });
        assertThat(thrownException.getMessage(), containsString("Cloud Auth username and password format should be"));
    }

    @Test
    public void testNullInputDoenstThrowAnException() {
        new CloudSettingAuth(null);
    }


    @Test
    public void testWhenGivenStringWhichIsCloudAuthSetTheString() {
        final CloudSettingAuth sut = new CloudSettingAuth("frodo:baggins");
        assertEquals("frodo", sut.getUsername());
        assertEquals("baggins", sut.getPassword().getValue());
        assertEquals("frodo:<password>", sut.toString());
    }
    //CS 427 Issue Link: https://github.com/elastic/logstash/issues/11193
    @Test
    public void testSpecialCharactersPassword() {
        final CloudSettingAuth sut = new CloudSettingAuth("frodo:=+$;@abcd");
        assertEquals("frodo", sut.getUsername());
        assertEquals("%3D+%24%3B%40abcd", sut.getPassword().getValue());
        assertEquals("frodo:<password>", sut.toString());
    }

}
