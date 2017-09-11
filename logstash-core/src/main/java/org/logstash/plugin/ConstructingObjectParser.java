package org.logstash.plugin;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * This is idea is taken largely from Elasticsearch but is unavailable as a library, so the code exists here as well.
 *
 * @param <Value> The object type to construct when `parse` is called.
 */
public class ConstructingObjectParser<Value> implements Function<Map<String, Object>, Value> {
    private final Function<Object[], Value> builder;
    private final Map<String, BiConsumer<Value, Object>> parsers = new LinkedHashMap<>();
    private final Map<String, BiConsumer<ArrayList<Object>, Object>> constructorArgs = new TreeMap<>();

    private final BiConsumer<Value, Object> CONSTRUCTOR_ARG = (a, b) -> {
        throw new UnsupportedOperationException("This function should never get called. It is a marker.");
    };

    public ConstructingObjectParser(Function<Object[], Value> builder) {
        this.builder = builder;
    }

    private static Integer integerTransform(Object object) {
        if (object instanceof Integer) {
            return (Integer) object;
        } else if (object instanceof String) {
            return Integer.parseInt((String) object);
        } else {
            throw new IllegalArgumentException("Value must be a number, but is a " + object.getClass());
        }
    }

    static String stringTransform(Object object) {
        if (object instanceof String) {
            return (String) object;
        } else if (object instanceof Number) {
            return object.toString();
        } else {
            throw new IllegalArgumentException("Value must be a string, but is a " + object.getClass());
        }
    }

    static <T> T objectTransform(Object object, ConstructingObjectParser<T> parser) {
        if (object instanceof Map) {
            // XXX: Fix this unchecked cast.
            return parser.apply((Map<String, Object>) object);
        } else {
            throw new IllegalArgumentException("Object value must be a Map, but is a " + object.getClass());
        }
    }

    /**
     * Add an field with an integer value.
     *
     * @param name the name of this field
     * @param consumer the function to call once the value is available
     */
    public void integer(String name, BiConsumer<Value, Integer> consumer) {
        declareField(name, consumer, ConstructingObjectParser::integerTransform);
    }

    /**
     * Declare an integer constructor argument.
     *
     * @param name the name of the field.
     */
    public void integer(String name) {
        declareConstructorArg(name, ConstructingObjectParser::integerTransform);
    }

    /**
     * Add a field with a string value.
     *
     * @param name the name of this field
     * @param consumer the function to call once the value is available
     */
    public void string(String name, BiConsumer<Value, String> consumer) {
        declareField(name, consumer, ConstructingObjectParser::stringTransform);
    }

    /**
     * Declare a constructor argument that is a string.
     *
     * @param name the name of this field.
     */
    public void string(String name) {
        declareConstructorArg(name, ConstructingObjectParser::stringTransform);
    }

    /**
     * Add a field with an object value
     *
     * @param name the name of this field
     * @param consumer the function to call once the value is available
     * @param parser The ConstructingObjectParser that will build the object
     * @param <T> The type of object to store as the value.
     */
    public <T> void object(String name, BiConsumer<Value, T> consumer, ConstructingObjectParser<T> parser) {
        declareField(name, consumer, (t) -> objectTransform(t, parser));
    }

    /**
     * Declare a constructor argument that is an object.
     *
     * @param name   the name of the field which represents this constructor argument
     * @param parser the ConstructingObjectParser that builds the object
     * @param <T>    The type of object created by the parser.
     */
    public <T> void object(String name, ConstructingObjectParser<T> parser) {
        declareConstructorArg(name, (t) -> objectTransform(t, parser));
    }

    private <T> void declareField(String name, BiConsumer<Value, T> consumer, Function<Object, T> transform) {
        BiConsumer<Value, Object> objConsumer = (value, object) -> consumer.accept(value, transform.apply(object));
        parsers.put(name, objConsumer);
    }

    private <T> void declareConstructorArg(String name, Function<Object, T> transform) {
        int position = constructorArgs.size();
        BiConsumer<ArrayList<Object>, Object> objConsumer = (array, object) -> array.add(position, transform.apply(object));
        constructorArgs.put(name, objConsumer);
    }

    /**
     * Construct an object using the given config.
     *
     * The intent is that a config map, such as one from a Logstash pipeline config:
     *
     *     input {
     *         example {
     *             some => "setting"
     *             goes => "here"
     *         }
     *     }
     *
     *  ... will know how to build an object for the above "example" input plugin.
     */
    public Value apply(Map<String, Object> config) {
        rejectUnknownFields();
        Value value = construct(config);

        // Now call all the object setters/etc
        for (Map.Entry<String, Object> entry : config.entrySet()) {
            String name = entry.getKey();
            if (constructorArgs.containsKey(name)) {
                // Skip constructor arguments
                continue;
            }

            BiConsumer<Value, Object> parser = parsers.get(name);
            assert parser != null

            parser.accept(value, entry.getValue());
        }

        return value;
    }

    private void rejectUnknownFields() {
        // Check for any unknown parameters.
        Set<String> unknown = new TreeSet<>();
        Set<String> known = new TreeSet<>();
        known.addAll(parsers.keySet());
        known.addAll(constructorArgs.keySet());
        unknown.removeAll(known);

        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("Unknown settings " + unknown);
        }
    }

    private Value construct(Map<String, Object> config) {
        // XXX: Implement constructor building.
        ArrayList<Object> args = new ArrayList<>(constructorArgs.size());
        // Constructor arguments. Any constructor argument is a *required* setting.
        for (Map.Entry<String, BiConsumer<ArrayList<Object>, Object>> argInfo : constructorArgs.entrySet()) {
            String name = argInfo.getKey();
            BiConsumer<ArrayList<Object>, Object> argsBuilder = argInfo.getValue();
            if (config.containsKey(name)) {
                argsBuilder.accept(args, config.get(name));
            } else {
                throw new IllegalArgumentException("Missing required argument '" + name + "' for " + getClass());
            }
        }

        return builder.apply(args.toArray());
    }
}
