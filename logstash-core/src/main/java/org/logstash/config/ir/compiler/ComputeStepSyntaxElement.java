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


package org.logstash.config.ir.compiler;

import com.google.common.annotations.VisibleForTesting;
import com.google.googlejavaformat.java.Formatter;
import com.google.googlejavaformat.java.FormatterException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.codehaus.commons.compiler.CompileException;
import org.codehaus.janino.Scanner;
import org.codehaus.commons.compiler.ISimpleCompiler;
import org.codehaus.janino.SimpleCompiler;

/**
 * One step of a compiled pipeline that compiles to a {@link Dataset}.
 */
public final class ComputeStepSyntaxElement<T extends Dataset> {

    public static final VariableDefinition CTOR_ARGUMENT =
        new VariableDefinition(Map.class, "arguments");

    private static final Path SOURCE_DIR = debugDir();

    /**
     * Global cache of runtime compiled classes to prevent duplicate classes being compiled.
     * across pipelines and workers.
     */
    private static final ConcurrentHashMap<ComputeStepSyntaxElement<?>, Class<? extends Dataset>> CLASS_CACHE
        = new ConcurrentHashMap<>(100);

    private static final AtomicLong DATASET_CLASS_INDEX = new AtomicLong(0);

    /**
     * Pattern to remove redundant {@code ;} from formatted code since {@link Formatter} does not
     * remove those.
     */
    private static final Pattern REDUNDANT_SEMICOLON = Pattern.compile("\n[ ]*;\n");

    private static final String CLASS_NAME_PLACEHOLDER = "CLASS_NAME_PLACEHOLDER";

    private static final Pattern CLASS_NAME_PLACEHOLDER_REGEX = Pattern.compile(CLASS_NAME_PLACEHOLDER);

    private final Iterable<MethodSyntaxElement> methods;

    private final ClassFields fields;

    private final Class<T> type;

    private final String normalizedSource;

    public static <T extends Dataset> ComputeStepSyntaxElement<T> create(
        final Iterable<MethodSyntaxElement> methods,
        final ClassFields fields,
        final Class<T> interfce)
    {
        return new ComputeStepSyntaxElement<>(methods, fields, interfce);
    }

    @VisibleForTesting
    public static int classCacheSize() {
        return CLASS_CACHE.size();
    }

    /*
     * Used in a test to clean start, with class loaders wiped out into Janino compiler and cleared the cached classes.
    * */
    @VisibleForTesting
    public static void cleanClassCache() {
        CLASS_CACHE.clear();
    }

    private ComputeStepSyntaxElement(
        final Iterable<MethodSyntaxElement> methods,
        final ClassFields fields,
        final Class<T> interfce)
    {
        this.methods = methods;
        this.fields = fields;
        type = interfce;

        // normalizes away the name of the class so that two classes of different name but otherwise
        // equivalent syntax get correctly compared by {@link #equals(Object)}.
        normalizedSource = generateCode(CLASS_NAME_PLACEHOLDER);
    }

    @SuppressWarnings("unchecked")
    public T instantiate() {
        try {
            final Class<? extends Dataset> clazz = compile();
            return (T) clazz.getConstructor(Map.class).newInstance(ctorArguments());
        } catch (final NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @SuppressWarnings("unchecked")
    /*
     * Returns a {@link Class<? extends Dataset>} for this {@link ComputeStepSyntaxElement}, reusing an existing
     * equivalent implementation from the global class cache when one is available, or otherwise compiling one.
     *
     * This method _is_ thread-safe, and uses the locking semantics of {@link ConcurrentHashMap#computeIfAbsent}.
     * To do so, it relies on {@link #hashCode()} and {@link #equals(Object)}.
     */
    private  Class<? extends Dataset> compile() {
        return CLASS_CACHE.computeIfAbsent(this, (__)->{
            try {
                final ISimpleCompiler compiler = new SimpleCompiler();
                final String name = String.format("CompiledDataset%d", DATASET_CLASS_INDEX.incrementAndGet());
                final String code = CLASS_NAME_PLACEHOLDER_REGEX.matcher(normalizedSource).replaceAll(name);
                if (SOURCE_DIR != null) {
                    final Path sourceFile = SOURCE_DIR.resolve(String.format("%s.java", name));
                    Files.write(sourceFile, code.getBytes(StandardCharsets.UTF_8));
                    compiler.cookFile(sourceFile.toFile());
                } else {
                    compiler.cook(code);
                }
                return (Class<T>) compiler.getClassLoader().loadClass(
                    String.format("org.logstash.generated.%s", name)
                );
            } catch (final CompileException | ClassNotFoundException | IOException ex) {
                throw new IllegalStateException(ex);
            }
        });
    }

    @Override
    public int hashCode() {
        return normalizedSource.hashCode();
    }

    @Override
    public boolean equals(final Object other) {
        return other instanceof ComputeStepSyntaxElement &&
            normalizedSource.equals(((ComputeStepSyntaxElement<?>) other).normalizedSource);
    }

    private String generateCode(final String name) {
        try {
            return REDUNDANT_SEMICOLON.matcher(new Formatter().formatSource(
                String.format(
                    "package org.logstash.generated;\npublic final class %s extends org.logstash.config.ir.compiler.BaseDataset implements %s { %s }",
                    name,
                    type.getName(),
                    SyntaxFactory.join(
                        fields.inlineAssigned().generateCode(), fieldsAndCtor(name),
                        combine(
                            StreamSupport.stream(methods.spliterator(), false)
                                .toArray(SyntaxElement[]::new)
                        )
                    )
                )
            )).replaceAll("\n");
        } catch (final FormatterException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Path debugDir() {
        Path sourceDir = null;
        try {
            final Path parentDir;
            final String dir = System.getProperty(Scanner.SYSTEM_PROPERTY_SOURCE_DEBUGGING_DIR);
            if (dir != null) {
                parentDir = Paths.get(dir);
                sourceDir = parentDir.resolve("org").resolve("logstash").resolve("generated");
                Files.createDirectories(sourceDir);
            }
        } catch (final IOException ex) {
            throw new IllegalStateException(ex);
        }
        return sourceDir;
    }

    /**
     * @return Map of constructor arguments, key is field's name, value is the instance of the parameter to pass.
     */
    private Map<String, Object> ctorArguments() {
        final Map<String, Object> result = new HashMap<>();
        fields.ctorAssigned().getFields().forEach(
            fieldDefinition ->
                result.put(fieldDefinition.getName(), fieldDefinition.getCtorArgument())
        );
        return result;
    }

    /**
     * Generates the Java code for defining one field and constructor argument for each given value.
     * constructor for
     * @return Java Source String
     */
    private String fieldsAndCtor(final String name) {
        final Closure constructor = new Closure();
        final FieldDeclarationGroup ctorFields = fields.ctorAssigned();
        for (final FieldDefinition field : ctorFields.getFields()) {
            if (field.getCtorArgument() != null) {
                final VariableDefinition fieldVar = field.asVariable();
                constructor.add(
                    SyntaxFactory.assignment(
                        fieldVar.access(),
                        SyntaxFactory.cast(
                            fieldVar.type,
                            CTOR_ARGUMENT.access().call(
                                "get",
                                SyntaxFactory.value(
                                    SyntaxFactory.join("\"", field.getName(), "\"")
                                )
                            )
                        )
                    )
                );
            }
        }
        return combine(
            ctorFields,
            MethodSyntaxElement.constructor(
                name, constructor.add(fields.afterInit())
            )
        );
    }

    /**
     * Renders the string concatenation of the given {@link SyntaxElement}, delimited by
     * line breaks.
     * @param parts Elements to concatenate
     * @return Java source
     */
    private static String combine(final SyntaxElement... parts) {
        return Arrays.stream(parts).map(SyntaxElement::generateCode)
            .collect(Collectors.joining("\n"));
    }
}
