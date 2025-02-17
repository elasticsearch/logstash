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

import org.logstash.config.ir.graph.Edge;
import org.logstash.config.ir.graph.Graph;
import org.logstash.config.ir.graph.Vertex;

import java.util.*;

public class TopologicalSort {
    public static class UnexpectedGraphCycleError extends Exception {
        private static final long serialVersionUID = 1778155790783320839L;

        UnexpectedGraphCycleError(Graph g) {
            super("Graph has cycles, is not a DAG! " + g);
        }
    }

    // Uses Kahn's algorithm to do a topological sort and detect cycles
    public static List<Vertex> sortVertices(Graph g) throws UnexpectedGraphCycleError {
        if (g.getEdges().size() == 0) return new ArrayList<>(g.getVertices());

        List<Vertex> sorted = new ArrayList<>(g.getVertices().size());

        Deque<Vertex> pending = new LinkedList<>(g.getRoots());

        Set<Edge> traversedEdges = new HashSet<>();

        while (!pending.isEmpty()) {
            Vertex currentVertex = pending.removeFirst();
            sorted.add(currentVertex);

            currentVertex.getOutgoingEdges().forEach(edge -> {
                traversedEdges.add(edge);
                Vertex toVertex = edge.getTo();
                if (toVertex.getIncomingEdges().stream().allMatch(traversedEdges::contains)) {
                    pending.add(toVertex);
                }
            });
        }

        // Check for cycles
        if (g.edges().noneMatch(traversedEdges::contains)) {
            throw new UnexpectedGraphCycleError(g);
        }

        return sorted;
    }

}
