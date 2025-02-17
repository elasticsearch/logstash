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

import org.logstash.common.Util;
import org.logstash.config.ir.Hashable;
import org.logstash.config.ir.SourceComponent;
import org.logstash.config.ir.InvalidIRException;
import org.logstash.common.SourceWithMetadata;
import org.logstash.config.ir.graph.algorithms.BreadthFirst;
import org.logstash.config.ir.graph.algorithms.GraphDiff;
import org.logstash.config.ir.graph.algorithms.TopologicalSort;

import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Graph implements SourceComponent, Hashable {
    private final Set<Vertex> vertices = new LinkedHashSet<>();
    private final Set<Edge> edges = new LinkedHashSet<>();
    private Map<Vertex, Integer> vertexRanks = new LinkedHashMap<>();
    private final Map<Vertex,Set<Edge>> outgoingEdgeLookup = new LinkedHashMap<>();
    private final Map<Vertex,Set<Edge>> incomingEdgeLookup = new LinkedHashMap<>();
    private List<Vertex> sortedVertices;

    // Builds a graph that has the specified vertices and edges
    // Note that this does *not* validate the result
    public Graph(Collection<Vertex> vertices, Collection<Edge> edges) throws InvalidIRException {
        for (Vertex vertex : vertices) { this.addVertex(vertex, false); }
        for (Edge edge : edges) { this.addEdge(edge, false); }
        this.refresh();
    }

    public Graph() {}

    public static Graph empty() {
        return new Graph();
    }

    public void addVertex(Vertex v) throws InvalidIRException {
        addVertex(v, true);
    }

    private void addVertex(Vertex v, boolean doRefresh) throws InvalidIRException {
        // If this belongs to another graph use a copy
        if (v.getGraph() != null && v.getGraph() != this) {
            throw new InvalidIRException("Attempted to add vertex already belonging to a graph!");
        }

        v.setGraph(this);

        this.vertices.add(v);

        if (doRefresh) this.refresh();
    }

    // Takes an arbitrary vertex from any graph and brings it into this one.
    // It may have to copy it. The actual vertex that gets used is returned
    public Vertex importVertex(Vertex v) throws InvalidIRException {
        if (v.getGraph() != this) {
            if (v.getGraph() == null) {
                this.addVertex(v);
                return v;
            } else {
                Vertex copy = v.copy();
                this.addVertex(copy);
                return copy;
            }
        } else {
            return v;
        }
    }

    public Vertex getVertexById(String id) {
        return this.vertices().filter(v -> v.getId().equals(id)).findAny().get();
    }

    private Graph addEdge(Edge e, boolean doRefresh) throws InvalidIRException {
        if (!(vertices.contains(e.getFrom()) && vertices.contains(e.getTo()))) {
            throw new InvalidIRException("Attempted to add edge referencing vertices not in this graph!");
        }

        this.edges.add(e);

        final BiFunction<Vertex, Set<Edge>, Set<Edge>> lookupComputeFunction = (vertex, edgeSet) -> {
            if (edgeSet == null) {
                edgeSet = new LinkedHashSet<>();
            }
            edgeSet.add(e);
            return edgeSet;
        };
        this.outgoingEdgeLookup.compute(e.getFrom(), lookupComputeFunction);
        this.incomingEdgeLookup.compute(e.getTo(), lookupComputeFunction);

        e.setGraph(this);
        if (doRefresh) this.refresh();
        return this;
    }

    protected Collection<Edge> getOutgoingEdges(Vertex v) {
        return this.outgoingEdgeLookup.getOrDefault(v, Collections.emptySet());
    }

    protected Collection<Edge> getIncomingEdges(Vertex v) {
        return this.incomingEdgeLookup.getOrDefault(v, Collections.emptySet());
    }

    // Returns a copy of this graph
    public Graph copy() throws InvalidIRException {
        return Graph.combine(this).graph;
    }

    // Returns a new graph that is the union of all provided graphs.
    // If a single graph is passed in this will return a copy of it
    public static GraphCombinationResult combine(Graph... graphs) throws InvalidIRException {
        Map<Vertex, Vertex> oldToNewVertices = new LinkedHashMap<>();
        Map<Edge,Edge> oldToNewEdges = new LinkedHashMap<>();

        for (Graph graph : graphs) {
            graph.vertices().forEachOrdered(v -> oldToNewVertices.put(v, v.copy()));

            for (Edge e : graph.getEdges()) {
                Edge copy = e.copy(oldToNewVertices.get(e.getFrom()), oldToNewVertices.get(e.getTo()));
                oldToNewEdges.put(e, copy);
            }
        }

        Graph newGraph = new Graph(oldToNewVertices.values(), oldToNewEdges.values());
        return new GraphCombinationResult(newGraph, oldToNewVertices, oldToNewEdges);
    }

    public static final class GraphCombinationResult {
        public final Graph graph;
        public final Map<Vertex, Vertex> oldToNewVertices;
        public final Map<Edge, Edge> oldToNewEdges;

        GraphCombinationResult(Graph graph, Map<Vertex, Vertex> oldToNewVertices, Map<Edge, Edge> oldToNewEdges) {
            this.graph = graph;
            this.oldToNewVertices = oldToNewVertices;
            this.oldToNewEdges = oldToNewEdges;
        }
    }

    /*
      Return a copy of this graph with the other graph's nodes to this one by connection this graph's leaves to
      the other graph's root
    */
    public Graph chain(Graph otherGraph) throws InvalidIRException {
        if (otherGraph.vertices.isEmpty()) return this.copy();
        if (this.isEmpty()) return otherGraph.copy();

        GraphCombinationResult combineResult = Graph.combine(this, otherGraph);

        // Build these lists here since we do mutate the graph in place later
        // This isn't strictly necessary, but makes things less confusing
        Collection<Vertex> fromLeaves = allLeaves().map(combineResult.oldToNewVertices::get).collect(Collectors.toList());
        Collection<Vertex> toRoots = otherGraph.roots().map(combineResult.oldToNewVertices::get).collect(Collectors.toList());

        return combineResult.graph.chain(fromLeaves, toRoots);
    }

    public Graph chain(Vertex... otherVertex) throws InvalidIRException {
        chain(this.getAllLeaves(), Arrays.asList(otherVertex));
        return this;
    }

    // This does *not* return a copy for performance reasons
    private Graph chain(Collection<Vertex> fromLeaves, Collection<Vertex> toVertices) throws InvalidIRException {
        for (Vertex leaf : fromLeaves) {
            for (Edge.EdgeFactory unusedEf : leaf.getUnusedOutgoingEdgeFactories()) {
                for (Vertex toVertex : toVertices) {
                    this.chainVertices(unusedEf, leaf, toVertex);
                }
            }
        }

        return this;
    }

    public Collection<Edge> chainVerticesById(String... vertexIds) throws InvalidIRException {
        return chainVerticesById(PlainEdge.factory, vertexIds);
    }

    public Collection<Edge> chainVerticesById(Edge.EdgeFactory edgeFactory, String... vertexIds) throws InvalidIRException {
        Vertex[] argVertices = new Vertex[vertexIds.length];
        for (int i = 0; i < vertexIds.length; i ++) {
            String id = vertexIds[i];
            Vertex v = getVertexById(id);
            if (v==null) throw new InvalidIRException("Could not chain vertex, id not found in graph: !" + id + "\n" + this);
            argVertices[i] = v;
        }
        return chainVertices(edgeFactory, argVertices);
    }

    // Will not validate the graph after running!
    // You must invoke validate the graph yourself
    // after invoking
    public Collection<Edge> chainVerticesUnsafe(Edge.EdgeFactory edgeFactory, Vertex... argVertices) throws InvalidIRException {
        List<Vertex> importedVertices = new ArrayList<>(argVertices.length);
        for (Vertex va : argVertices) {
            importedVertices.add(this.importVertex(va));
        }

        List<Edge> newEdges = new ArrayList<>();
        for (int i = 0; i < importedVertices.size()-1; i++) {
            Vertex from = importedVertices.get(i);
            Vertex to = importedVertices.get(i+1);

            this.addVertex(from, false);
            this.addVertex(to, false);

            Edge edge = edgeFactory.make(from, to);
            newEdges.add(edge);
            this.addEdge(edge, false);
        }

        refresh();

        return newEdges;
    }

    public Collection<Edge> chainVertices(Edge.EdgeFactory edgeFactory, Vertex... argVertices) throws InvalidIRException {
        Collection<Edge> edges = chainVerticesUnsafe(edgeFactory, argVertices);
        return edges;
    }

    public Edge chainVertices(Vertex a, Vertex b) throws InvalidIRException {
        return chainVertices(PlainEdge.factory, a, b).stream().findFirst().get();
    }

    public Collection<Edge> chainVertices(Vertex... vertices) throws InvalidIRException {
        return chainVertices(PlainEdge.factory, vertices);
    }

    public Collection<Edge> chainVertices(boolean bool, Vertex... vertices) throws InvalidIRException {
        Edge.EdgeFactory factory = bool ? BooleanEdge.trueFactory : BooleanEdge.falseFactory;
        return chainVertices(factory, vertices);
    }

    // Many of the operations we perform involve modifying one graph by adding vertices/edges
    // from another. This method ensures that all the vertices/edges we know about having been pulled into
    // this graph. Methods in this class that add or remove externally provided vertices/edges
    // should call this method to ensure that the rest of the graph these items depend on are pulled
    // in.
    public void refresh() throws InvalidIRException {
        this.calculateRanks();
        this.vertices.forEach(Vertex::clearCache);
        this.calculateTopologicalSort();
    }

    private void calculateTopologicalSort() throws InvalidIRException {
        try {
            this.sortedVertices = TopologicalSort.sortVertices(this);
        } catch (TopologicalSort.UnexpectedGraphCycleError unexpectedGraphCycleError) {
            throw new InvalidIRException("Graph is not a dag!", unexpectedGraphCycleError);
        }
    }

    private void calculateRanks() {
        vertexRanks = BreadthFirst.breadthFirst(this.getRoots()).vertexDistances;
    }

    public Integer rank(Vertex vertex) {
        Integer rank = vertexRanks.get(vertex);
        // This should never happen
        if (rank == null) throw new RuntimeException("Attempted to get rank from vertex where it is not yet calculated: " + this);
        return rank;
    }

    public void validate() throws InvalidIRException {
        if (this.isEmpty()) return;

        if (this.getVertices().stream().noneMatch(Vertex::isLeaf)) {
            throw new InvalidIRException("Graph has no leaf vertices!\n" + this.toString());
        }

        // Check for duplicate IDs in the config
        List<String> duplicateIdErrorMessages = this.vertices()
                .collect(Collectors.groupingBy(Vertex::getId))
                .values()
                .stream()
                .filter(group -> group.size() > 1)
                .map(group -> {
                    return "ID: " + group.stream().findAny().get().getId() + " " +
                            group.stream().map(Object::toString).collect(Collectors.joining("\n"));
                })
                .collect(Collectors.toList());

        if (!duplicateIdErrorMessages.isEmpty()) {
            String dupeErrors = duplicateIdErrorMessages.stream().collect(Collectors.joining("\n"));
            throw new InvalidIRException("Config has duplicate Ids: \n" + dupeErrors);
        }
    }


    public Stream<Vertex> roots() {
        return vertices.stream().filter(Vertex::isRoot);
    }

    public Collection<Vertex> getRoots() {
        return roots().collect(Collectors.toList());
    }

    // Vertices which are partially leaves in that they support multiple
    // outgoing edge types but only have one or fewer attached
    public Stream<Vertex> allLeaves() {
        return vertices().filter(Vertex::isPartialLeaf);
    }

    // Get all leaves whether partial or not
    public Collection<Vertex> getAllLeaves() {
        return allLeaves().collect(Collectors.toList());
    }

    public Stream<Vertex> leaves() {
        return vertices().filter(Vertex::isLeaf);
    }

    public Collection<Vertex> getLeaves() {
        return leaves().collect(Collectors.toList());
    }

    public Set<Vertex> getVertices() {
        return vertices;
    }

    public Collection<Edge> getEdges() {
        return edges;
    }

    public String toString() {
        final Stream<Edge> edgesToFormat = sortedEdges();
        final String edgelessVerticesStr;
        if (this.isolatedVertices().findAny().isPresent()) {
            edgelessVerticesStr = "\n== Vertices Without Edges ==\n" +
                    this.isolatedVertices().map(Vertex::toString).collect(Collectors.joining("\n"));
        } else {
            edgelessVerticesStr = "";
        }

        return "**GRAPH**\n" +
               "Vertices: " + this.vertices.size()+ " Edges: " + this.edges().count() + "\n" +
               "----------------------" +
               edgesToFormat.map(Edge::toString).collect(Collectors.joining("\n")) +
               edgelessVerticesStr +
               "\n**GRAPH**";
    }

    public Stream<Vertex> isolatedVertices() {
        return vertices().filter(v -> v.getOutgoingEdges().isEmpty() && v.getIncomingEdges().isEmpty());
    }

    public List<Vertex> getSortedVertices() {
        return this.sortedVertices;
    }

    public Stream<Edge> sortedEdges() {
        return getSortedVertices().stream().
                flatMap(Vertex::outgoingEdges);
    }

    public List<Vertex> getSortedVerticesBefore(Vertex end) {
        return getSortedVerticesBetween(null, end);
    }

    public List<Vertex> getSortedVerticesAfter(Vertex start) {
        return getSortedVerticesBetween(start, null);
    }

    public List<Vertex> getSortedVerticesBetween(Vertex start, Vertex end) {
        int startIndex = start == null ? 0 : sortedVertices.indexOf(start);
        int endIndex = end == null ? sortedVertices.size() : sortedVertices.indexOf(end);
        return sortedVertices.subList(startIndex+1, endIndex);
    }

    @Override
    public boolean sourceComponentEquals(SourceComponent sourceComponent) {
        if (sourceComponent == this) return true;
        if (sourceComponent instanceof Graph) {
            Graph otherGraph = (Graph) sourceComponent;
            GraphDiff.DiffResult diff = GraphDiff.diff(this, otherGraph);
            return diff.isIdentical();

        }
        return false;
    }

    // returns true if this graph has a .sourceComponentEquals equivalent edge
    public boolean hasEquivalentEdge(Edge otherE) {
        return edges().anyMatch(e -> e.sourceComponentEquals(otherE));
    }

    public boolean hasEquivalentVertex(Vertex otherV) {
        return vertices().anyMatch(v -> v.sourceComponentEquals(otherV));
    }

    @Override
    public SourceWithMetadata getSourceWithMetadata() {
        return null;
    }

    public boolean isEmpty() {
        return vertices.isEmpty();
    }

    public Stream<Vertex> vertices() {
        return this.vertices.stream();
    }

    public Stream<Edge> edges() {
        return this.edges.stream();
    }

    public String uniqueHash() {
        return Util.digest(this.vertices().
                filter(v -> !(v instanceof QueueVertex) && !(v instanceof SeparatorVertex)). // has no metadata
                map(Vertex::getSourceWithMetadata).
                map(SourceWithMetadata::uniqueHash).
                sorted().
                collect(Collectors.joining()));
    }
}
