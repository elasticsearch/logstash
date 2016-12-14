package org.logstash.config.ir.graph;

import org.logstash.config.ir.IHashable;
import org.logstash.config.ir.ISourceComponent;
import org.logstash.config.ir.InvalidIRException;
import org.logstash.config.ir.SourceMetadata;
import org.logstash.config.ir.graph.algorithms.BreadthFirst;
import org.logstash.config.ir.graph.algorithms.GraphDiff;

import java.lang.reflect.Array;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by andrewvc on 9/15/16.
 */
public class Graph implements ISourceComponent, IHashable {
    private final Set<Vertex> vertices = new HashSet<>();
    private final Set<Edge> edges = new HashSet<>();
    private Map<Vertex, Integer> vertexRanks = new HashMap<>();
    private final Map<Vertex,Set<Edge>> outgoingEdgeLookup = new HashMap<>();
    private final Map<Vertex,Set<Edge>> incomingEdgeLookup = new HashMap<>();


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

    // Use threadVertices instead
    private Graph addEdge(Edge e) throws InvalidIRException {
        return addEdge(e, true);
    }

    private Graph addEdge(Edge e, boolean doRefresh) throws InvalidIRException {
        if (!(this.getVertices().contains(e.getFrom()) && this.getVertices().contains(e.getTo()))) {
            throw new InvalidIRException("Attempted to add edge referencing vertices not in this graph!");
        }

        this.edges.add(e);

        BiFunction<Vertex, Set<Edge>, Set<Edge>> lookupComputeFunction = (vertex, edgeSet) -> {
            if (edgeSet == null) edgeSet = new HashSet<>();
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
        Map<Vertex, Vertex> oldToNewVertices = new HashMap<>();
        Map<Edge,Edge> oldToNewEdges = new HashMap<>();

        for (Graph graph : graphs) {
            graph.vertices().forEach(v -> oldToNewVertices.put(v, v.copy()));

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
        if (otherGraph.getVertices().size() == 0) return this.copy();
        if (this.isEmpty()) return otherGraph.copy();

        GraphCombinationResult combineResult = Graph.combine(this, otherGraph);

        // Build these lists here since we do mutate the graph in place later
        // This isn't strictly necessary, but makes things less confusing
        Collection<Vertex> fromLeaves = allLeaves().map(combineResult.oldToNewVertices::get).collect(Collectors.toSet());
        Collection<Vertex> toRoots = otherGraph.roots().map(combineResult.oldToNewVertices::get).collect(Collectors.toSet());

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
                    this.threadVertices(unusedEf, leaf, toVertex);
                }
            }
        }

        return this;
    }

    public Collection<Edge> threadVerticesById(String... vertexIds) throws InvalidIRException {
        return threadVerticesById(PlainEdge.factory, vertexIds);
    }

    public Collection<Edge> threadVerticesById(Edge.EdgeFactory edgeFactory, String... vertexIds) throws InvalidIRException {
        Vertex[] argVertices = new Vertex[vertexIds.length];
        for (int i = 0; i < vertexIds.length; i ++) {
            String id = vertexIds[i];
            Vertex v = getVertexById(id);
            if (v==null) throw new InvalidIRException("Could not thread vertex, id not found in graph: !" + id + "\n" + this);
            argVertices[i] = v;
        }
        return threadVertices(edgeFactory, argVertices);
    }

    public Collection<Edge> threadVertices(Edge.EdgeFactory edgeFactory, Vertex... argVertices) throws InvalidIRException {
        List<Vertex> importedVertices = new ArrayList<>(argVertices.length);
        for (Vertex va : argVertices) {
            importedVertices.add(this.importVertex(va));
        }

        List<Edge> newEdges = new ArrayList<>();
        for (int i = 0; i < importedVertices.size()-1; i++) {
            Vertex from = importedVertices.get(i);
            Vertex to = importedVertices.get(i+1);

            this.addVertex(from);
            this.addVertex(to);

            Edge edge = edgeFactory.make(from, to);
            newEdges.add(edge);
            this.addEdge(edge);
        }

        refresh();

        return newEdges;
    }

    public Edge threadVertices(Vertex a, Vertex b) throws InvalidIRException {
        return threadVertices(PlainEdge.factory, a, b).stream().findFirst().get();
    }

    public Collection<Edge> threadVertices(Vertex... vertices) throws InvalidIRException {
        return threadVertices(PlainEdge.factory, vertices);
    }

    public Collection<Edge> threadVertices(boolean bool, Vertex... vertices) throws InvalidIRException {
        Edge.EdgeFactory factory = bool ? BooleanEdge.trueFactory : BooleanEdge.falseFactory;
        return threadVertices(factory, vertices);
    }

    // Many of the operations we perform involve modifying one graph by adding vertices/edges
    // from another. This method ensures that all the vertices/edges we know about having been pulled into
    // this graph. Methods in this class that add or remove externally provided vertices/edges
    // should call this method to ensure that the rest of the graph these items depend on are pulled
    // in.
    public void refresh() throws InvalidIRException {
        this.calculateRanks();
        this.validate();
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

    public Map<String, List<Vertex>> verticesByHash() {
        return this.vertices().collect(Collectors.groupingBy(Vertex::uniqueHash));
    }

    public void validate() throws InvalidIRException {
        if (this.getVertices().stream().noneMatch(Vertex::isLeaf)) {
            throw new InvalidIRException("Graph has no leaf vertices!" + this.toString());
        }

        List<List<Vertex>> duplicates = verticesByHash().values().stream().filter((group) -> group.size() > 1).collect(Collectors.toList());
        if (!duplicates.isEmpty()) {
            Stream<String> errorMessageGroups = duplicates.stream().
                    map((group) -> group.stream().map(Object::toString).collect(Collectors.joining("===")));

            String joinedErrorMessageGroups = errorMessageGroups.collect(Collectors.joining("\n---\n"));

            throw new InvalidIRException("Some nodes on the graph are fully redundant!\n" + joinedErrorMessageGroups);
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
        return vertices.stream().filter(Vertex::isPartialLeaf);
    }

    // Get all leaves whether partial or not
    public Collection<Vertex> getAllLeaves() {
        return allLeaves().collect(Collectors.toList());
    }

    public Stream<Vertex> leaves() {
        return vertices.stream().filter(Vertex::isLeaf);
    }

    public Collection<Vertex> getLeaves() {
        return leaves().collect(Collectors.toList());
    }

    public Set<Vertex> getVertices() {
        return vertices;
    }

    public Set<Edge> getEdges() {
        return edges;
    }

    public String toString() {
        Stream<Edge> edgesToFormat;
        try {
            edgesToFormat = getSortedEdges().stream();
        } catch (InvalidIRException e) {
            edgesToFormat = edges.stream();
        }

        String edgelessVerticesStr;
        if (this.isolatedVertices().count() > 0) {
            edgelessVerticesStr = "\n== Vertices Without Edges ==\n" +
                    this.isolatedVertices().map(Vertex::toString).collect(Collectors.joining("\n"));
        } else {
            edgelessVerticesStr = "";
        }

        return "<GRAPH>\n" +
                edgesToFormat.map(Edge::toString).collect(Collectors.joining("\n")) +
                edgelessVerticesStr +
                "\n</GRAPH>";
    }

    public Stream<Vertex> isolatedVertices() {
        return this.getVertices().stream().filter(v -> v.getOutgoingEdges().isEmpty() && v.getIncomingEdges().isEmpty());
    }

    // Uses Kahn's algorithm to do a topological sort and detect cycles
    public List<Vertex> getSortedVertices() throws InvalidIRException {
        if (this.edges.size() == 0) return new ArrayList(this.vertices);

        List<Vertex> sorted = new ArrayList<>(this.vertices.size());

        Deque<Vertex> pending = new LinkedList<>();
        pending.addAll(this.getRoots());

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
        if (this.edges.stream().noneMatch(traversedEdges::contains)) {
            throw new InvalidIRException("Graph has cycles, is not a DAG! " + this.edges);
        }

        return sorted;
    }

    public List<Edge> getSortedEdges() throws InvalidIRException {
        return getSortedVertices().stream().
                flatMap(Vertex::outgoingEdges).
                collect(Collectors.toList());
    }

    public List<Vertex> getSortedVerticesBefore(Vertex end) throws InvalidIRException {
        return getSortedVerticesBetween(null, end);
    }

    public List<Vertex> getSortedVerticesAfter(Vertex start) throws InvalidIRException {
        return getSortedVerticesBetween(start, null);
    }

    public List<Vertex> getSortedVerticesBetween(Vertex start, Vertex end) throws InvalidIRException {
        List<Vertex> sortedVertices = getSortedVertices();

        int startIndex = start == null ? 0 : sortedVertices.indexOf(start);
        int endIndex = end == null ? sortedVertices.size() : sortedVertices.indexOf(end);

        return sortedVertices.subList(startIndex+1, endIndex);
    }

    @Override
    public boolean sourceComponentEquals(ISourceComponent sourceComponent) {
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
        return this.getEdges().stream().anyMatch(e -> e.sourceComponentEquals(otherE));
    }

    public boolean hasEquivalentVertex(Vertex otherV) {
        return this.getVertices().stream().anyMatch(v -> v.sourceComponentEquals(otherV));
    }

    @Override
    public SourceMetadata getMeta() {
        return null;
    }

    public boolean isEmpty() {
        return (this.getVertices().size() == 0);
    }

    public Stream<Vertex> vertices() {
        return this.vertices.stream();
    }

    public Stream<Edge> edges() {
        return this.edges.stream();
    }

    @Override
    public String hashSource() {
        return this.vertices.stream().map(Vertex::hashSource).sorted().collect(Collectors.joining("\n"));
    }
}
