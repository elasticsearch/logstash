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


package org.logstash.config.ir.graph.algorithms;

import org.logstash.config.ir.graph.Vertex;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class BreadthFirst {
    public static BfsResult breadthFirst(Collection<Vertex> roots) {
        return breadthFirst(roots, false, null);
    }

    /* This isn't as pretty as the DFS search with its streaminess, but for our current uses we only really
    *  care about using this to get the calculated vertexDistances, so that's fine. */
    public static BfsResult breadthFirst(Collection<Vertex> roots,
                                        boolean reverse,
                                        Consumer<Map.Entry<Vertex, Integer>> consumer
                                        ) {
    Map<Vertex, Integer> vertexDistances = new HashMap<>();

    Deque<Vertex> queue = new ArrayDeque<>(roots);
    roots.forEach(v -> vertexDistances.put(v, 0));

    while (!queue.isEmpty()) {
        Vertex currentVertex = queue.removeFirst();
        Integer currentDistance = vertexDistances.get(currentVertex);

        if (consumer != null) {
            consumer.accept(new AbstractMap.SimpleImmutableEntry<>(currentVertex, currentDistance));
        }

        Stream<Vertex> nextVertices = reverse ? currentVertex.incomingVertices() : currentVertex.outgoingVertices();
        nextVertices.forEach(nextVertex -> {
            if (vertexDistances.get(nextVertex) == null) {
                vertexDistances.put(nextVertex, currentDistance+1);
                queue.push(nextVertex);
            }
        });
    }

    return new BfsResult(vertexDistances);
}

    public static final class BfsResult {
        public final Map<Vertex, Integer> vertexDistances;

        BfsResult(Map<Vertex, Integer> vertexDistances) {
            this.vertexDistances = vertexDistances;
        }

        public Collection<Vertex> getVertices() {
            return vertexDistances.keySet();
        }
    }
}
