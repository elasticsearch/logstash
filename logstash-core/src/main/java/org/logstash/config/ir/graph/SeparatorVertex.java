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


package org.logstash.config.ir.graph;

import org.logstash.common.IncompleteSourceWithMetadataException;
import org.logstash.common.Util;
import org.logstash.config.ir.SourceComponent;
import org.logstash.common.SourceWithMetadata;

import java.util.Objects;

public final class SeparatorVertex extends Vertex {

    public SeparatorVertex(String id) throws IncompleteSourceWithMetadataException {
        super(new SourceWithMetadata("internal", id, 0,0,"separator"), id);
    }

    @Override
    public String toString() {
        return this.getId();
    }

    @Override
    public SeparatorVertex copy() {
        try {
            return new SeparatorVertex(this.getId());
        } catch (IncompleteSourceWithMetadataException e) {
            // Never happens
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean sourceComponentEquals(SourceComponent other) {
        return other instanceof SeparatorVertex && Objects.equals(((SeparatorVertex) other).getId(), this.getId());
    }

    // Special vertices really have no metadata
    @Override
    public SourceWithMetadata getSourceWithMetadata() {
        return null;
    }

    @Override
    public String uniqueHash() {
        return Util.digest("SEPARATOR_" + this.getId());
    }
}
