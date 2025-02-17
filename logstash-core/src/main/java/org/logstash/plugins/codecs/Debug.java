package org.logstash.plugins.codecs;

import co.elastic.logstash.api.Codec;
import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.logstash.ObjectMappers.JSON_MAPPER;

/**
 * An encode-only codec that prints events as pretty-printed JSON somewhat similar
 * to the "rubydebug" codec.
 */
@LogstashPlugin(name = "debug")
public class Debug implements Codec {

    private static final PluginConfigSpec<Boolean> METADATA_CONFIG =
            PluginConfigSpec.booleanSetting("metadata", false);

    private static final byte[] NEWLINE_BYTES = System.lineSeparator().getBytes();
    private final Context context;
    private final boolean metadata;
    private final String id;

    private final Function<Event, Map<String, Object>> dataFunction;

    /**
     * Required constructor.
     *
     * @param configuration Logstash Configuration
     * @param context       Logstash Context
     */
    public Debug(final Configuration configuration, final Context context) {
        this(context, configuration.get(METADATA_CONFIG));
    }

    private Debug(Context context, boolean metadata) {
        this.context = context;
        this.metadata = metadata;
        this.dataFunction = this.metadata ? this::withMetadata : this::withoutMetadata;
        this.id = UUID.randomUUID().toString();
    }

    @Override
    public void decode(ByteBuffer buffer, Consumer<Map<String, Object>> eventConsumer) {
        throw new UnsupportedOperationException("The debug codec supports only encoding");
    }

    @Override
    public void flush(ByteBuffer buffer, Consumer<Map<String, Object>> eventConsumer) {
        throw new UnsupportedOperationException("The debug codec supports only encoding");
    }

    @Override
    public void encode(Event event, OutputStream output) throws IOException {
        output.write(JSON_MAPPER
                .writerWithDefaultPrettyPrinter()
                .writeValueAsBytes(dataFunction.apply(event)));
        output.write(NEWLINE_BYTES);
    }

    private Map<String, Object> withoutMetadata(Event e) {
        return e.getData();
    }

    private Map<String, Object> withMetadata(Event e) {
        Map<String, Object> withMetadata = e.toMap();
        withMetadata.put(org.logstash.Event.METADATA, e.getMetadata());
        return withMetadata;
    }

    @Override
    public Codec cloneCodec() {
        return new Debug(context, metadata);
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return Collections.singletonList(METADATA_CONFIG);
    }

    @Override
    public String getId() {
        return id;
    }
}
