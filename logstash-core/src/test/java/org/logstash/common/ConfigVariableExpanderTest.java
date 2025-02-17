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

import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Test;
import org.logstash.plugins.ConfigVariableExpander;
import org.logstash.secret.SecretIdentifier;
import org.logstash.secret.SecretVariable;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import static org.hamcrest.Matchers.instanceOf;
import static org.logstash.secret.store.SecretStoreFactoryTest.MemoryStore;

public class ConfigVariableExpanderTest {

    @Test
    public void testNonStringValueReturnsUnchanged() {
        long nonStringValue = 42L;
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.emptyMap());
        Object expandedValue = cve.expand(nonStringValue);
        Assert.assertEquals(nonStringValue, expandedValue);
    }

    @Test
    public void testExpansionWithoutVariable() throws Exception {
        String key = "foo";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.emptyMap());
        String expandedValue = (String) cve.expand(key);
        Assert.assertEquals(key, expandedValue);
    }

    @Test
    public void testSimpleExpansion() throws Exception {
        String key = "foo";
        String val = "bar";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.singletonMap(key, val));

        String expandedValue = (String) cve.expand("${" + key + "}");
        Assert.assertEquals(val, expandedValue);
    }

    @Test
    public void testPartialExpansion() throws Exception {
        String key = "foo";
        String val = "bar";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.singletonMap(key, val));

        String expandedValue = (String) cve.expand("test_partial_${" + key + "}");
        Assert.assertEquals("test_partial_"+val, expandedValue);
    }

    @Test
    public void testTwoExpansions() throws Exception {
        String key1 = "foo";
        String key2 = "bar";
        String val1 = "foo_val";
        String val2 = "bar_val";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Map.of(key1, val1, key2, val2));

        String expandedValue = (String) cve.expand("${" + key1 + "}${" + key2 + "}");
        Assert.assertEquals(val1+val2, expandedValue);
    }

    @Test
    public void testExpansionWithDefaultValue() throws Exception {
        String key = "foo";
        String val = "bar";
        String defaultValue = "baz";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.emptyMap());

        String expandedValue = (String) cve.expand("${" + key + ":" + defaultValue + "}");
        Assert.assertEquals(defaultValue, expandedValue);
    }

    @Test
    public void testExpansionWithoutValueThrows() throws Exception {
        String key = "foo";
        ConfigVariableExpander cve = getFakeCve(Collections.emptyMap(), Collections.emptyMap());

        try {
            String expandedValue = (String) cve.expand("${" + key + "}");
            Assert.fail("Exception should have been thrown");
        } catch (IllegalStateException ise) {
            Assert.assertTrue(ise.getMessage().startsWith("Cannot evaluate"));
        }
    }

    @Test
    public void testPrecedenceOfSecretStoreValue() throws Exception {
        String key = "foo";
        String ssVal = "ssbar";
        String evVal = "evbar";
        String defaultValue = "defaultbar";
        ConfigVariableExpander cve = getFakeCve(
                Collections.singletonMap(key, ssVal),
                Collections.singletonMap(key, evVal));

        String expandedValue = (String) cve.expand("${" + key + ":" + defaultValue + "}");
        Assert.assertEquals(ssVal, expandedValue);
    }

    @Test
    public void testPrecedenceOfSecretStoreValueKeepingSecrets() {
        String key = "foo";
        String ssVal = "ssbar";
        String evVal = "evbar";
        String defaultValue = "defaultbar";
        ConfigVariableExpander cve = getFakeCve(
                Collections.singletonMap(key, ssVal),
                Collections.singletonMap(key, evVal));

        Object expandedValue = cve.expand("${" + key + ":" + defaultValue + "}", true);
        MatcherAssert.assertThat(expandedValue, instanceOf(SecretVariable.class));
        Assert.assertEquals(ssVal, ((SecretVariable) expandedValue).getSecretValue());
    }

    @Test
    public void testPrecedenceOfEnvironmentVariableValue() throws Exception {
        String key = "foo";
        String evVal = "evbar";
        String defaultValue = "defaultbar";
        ConfigVariableExpander cve = getFakeCve(
                Collections.emptyMap(),
                Collections.singletonMap(key, evVal));

        String expandedValue = (String) cve.expand("${" + key + ":" + defaultValue + "}");
        Assert.assertEquals(evVal, expandedValue);
    }

    // used by tests IfVertexTest, EventConditionTest
    public static ConfigVariableExpander getFakeCve(
            final Map<String, Object> ssValues, final Map<String, String> envVarValues) {

        MemoryStore ms = new MemoryStore();
        for (Map.Entry<String, Object> e : ssValues.entrySet()) {
            if (e.getValue() instanceof String) {
                ms.persistSecret(new SecretIdentifier(e.getKey()),
                        ((String) e.getValue()).getBytes(StandardCharsets.UTF_8));
            }
        }
        return new ConfigVariableExpander(ms, envVarValues::get);
    }

}
