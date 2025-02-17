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

import co.elastic.logstash.api.Password;
import org.logstash.RubyUtil;
import java.util.HashMap;

/**
 * Represents and decode credentials to access Elastic cloud instance.
 * */
public class CloudSettingAuth {

    private String original;
    private String username;
    private Password password;
	private String specialCharacters = "=$;@";
	private static HashMap <String, String> charMap;
	static {	
		charMap = new HashMap<>();
		charMap.put("=", "%3D");
		charMap.put("$", "%24");
		charMap.put(";", "%3B");
		charMap.put("@", "%40");
		charMap.put("%", "%25");
	}

    /**
    * Verifies cloud authentication string using passed in username and password.
    * Hides password to any external observers.
    *
    * @param value original username and password string
    * @return null if input is null
    */
    public CloudSettingAuth(String value) {
        if (value == null) {
            return;
        }
        this.original = value;
        final String[] parts = this.original.split(":");
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw RubyUtil.RUBY.newArgumentError("Cloud Auth username and password format should be \"<username>:<password>\".");
        }
		
        this.username = parts[0];
        this.password = new Password(encodeSpecialCharacters(parts[1]));
    }

    public String getOriginal() {
        return original;
    }

    public String getUsername() {
        return username;
    }

    public Password getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return String.join(":", username, password.toString());
    }
	
	//CS427 Issue Link: https://github.com/elastic/logstash/issues/11193
	private String encodeSpecialCharacters(String value) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < value.length(); i++)
		{
			String check = Character.toString(value.charAt(i));
			if (specialCharacters.contains(check)){
				buf.append(charMap.get(check));
			}
			else {
				buf.append(check);
			}
		}
		return buf.toString();
		
	}
}
