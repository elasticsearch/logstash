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


package org.logstash.plugins;

import org.logstash.common.EnvironmentVariableProvider;
import org.logstash.secret.SecretIdentifier;
import org.logstash.secret.SecretVariable;
import org.logstash.secret.store.SecretStore;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Expand the configuration variables used in pipeline configuration, bringing them from secret store or from the
 * environment.
 * */
public class ConfigVariableExpander implements AutoCloseable {

    private static String SUBSTITUTION_PLACEHOLDER_REGEX = "\\$\\{(?<name>[a-zA-Z_.][a-zA-Z0-9_.]*)(:(?<default>[^}]*))?}";

    private Pattern substitutionPattern = Pattern.compile(SUBSTITUTION_PLACEHOLDER_REGEX);
    private SecretStore secretStore;
    private EnvironmentVariableProvider envVarProvider;

    /**
     * Creates a ConfigVariableExpander that doesn't lookup any secreted placeholder.
     *
     * @param envVarProvider EnvironmentVariableProvider to use as source of substitutions
     * @return an variable expander that uses envVarProvider as source
     * */
    public static ConfigVariableExpander withoutSecret(EnvironmentVariableProvider envVarProvider) {
        return new ConfigVariableExpander(null, envVarProvider);
    }

    public ConfigVariableExpander(SecretStore secretStore, EnvironmentVariableProvider envVarProvider) {
        this.secretStore = secretStore;
        this.envVarProvider = envVarProvider;
    }

    /**
     * Replace all substitution variable references and returns the substituted value or the original value
     * if a substitution cannot be made.
     *
     * Substitution variables have the patterns: <code>${VAR}</code> or <code>${VAR:defaultValue}</code>
     *
     * If a substitution variable is found, the following precedence applies:
     *   Secret store value
     *   Environment entry value
     *   Default value if provided in the pattern
     *   Exception raised
     *
     * If a substitution variable is not found, the value is return unchanged
     *
     * @param value Config value in which substitution variables, if any, should be replaced.
     * @param keepSecrets True if secret stores resolved variables must be kept secret in a Password instance
     * @return Config value with any substitution variables replaced
     */
    public Object expand(Object value, boolean keepSecrets) {
        if (!(value instanceof String)) {
            return value;
        }

        String variable = (String) value;

        Matcher m = substitutionPattern.matcher(variable);

        if (m.matches()) {
            return replaceMatchedVariables(keepSecrets, m, variable);
        } else if (m.find()) {
            return m.replaceAll(matchResult -> replaceMatchedVariables(false, m, variable).toString());
        }

        return variable;
    }

    private Object replaceMatchedVariables(boolean keepSecrets, Matcher m, String variable) {
        String variableName = m.group("name");

        if (secretStore != null) {
            byte[] ssValue = secretStore.retrieveSecret(new SecretIdentifier(variableName));
            if (ssValue != null) {
                if (keepSecrets) {
                    return new SecretVariable(variableName, new String(ssValue, StandardCharsets.UTF_8));
                } else {
                    return new String(ssValue, StandardCharsets.UTF_8);
                }
            }
        }

        if (envVarProvider != null) {
            String evValue = envVarProvider.get(variableName);
            if (evValue != null) {
                return evValue;
            }
        }

        String defaultValue = m.group("default");
        if (defaultValue == null) {
            throw new IllegalStateException(String.format(
                    "Cannot evaluate `%s`. Replacement variable `%s` is not defined in a Logstash " +
                            "secret store or an environment entry and there is no default value given.",
                    variable, variableName));
        }
        return defaultValue;
    }

    public Object expand(Object value) {
        return expand(value, false);
    }

    @Override
    public void close() {
        // most keystore implementations will have close() methods

    }
}
