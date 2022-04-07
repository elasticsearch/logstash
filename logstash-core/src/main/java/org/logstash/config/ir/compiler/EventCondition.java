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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import org.jruby.Ruby;
import org.jruby.RubyRegexp;
import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.logstash.ConvertedList;
import org.logstash.ConvertedMap;
import org.logstash.Event;
import org.logstash.FieldReference;
import org.logstash.RubyUtil;
import org.logstash.Rubyfier;
import org.logstash.Valuefier;
import org.logstash.config.ir.expression.BinaryBooleanExpression;
import org.logstash.config.ir.expression.BooleanExpression;
import org.logstash.config.ir.expression.EventValueExpression;
import org.logstash.config.ir.expression.Expression;
import org.logstash.config.ir.expression.RegexValueExpression;
import org.logstash.config.ir.expression.ValueExpression;
import org.logstash.config.ir.expression.binary.And;
import org.logstash.config.ir.expression.binary.Eq;
import org.logstash.config.ir.expression.binary.Gt;
import org.logstash.config.ir.expression.binary.Gte;
import org.logstash.config.ir.expression.binary.In;
import org.logstash.config.ir.expression.binary.Lt;
import org.logstash.config.ir.expression.binary.Lte;
import org.logstash.config.ir.expression.binary.Neq;
import org.logstash.config.ir.expression.binary.Or;
import org.logstash.config.ir.expression.binary.RegexEq;
import org.logstash.config.ir.expression.unary.Not;
import org.logstash.config.ir.expression.unary.Truthy;
import org.logstash.execution.PipelineException;
import org.logstash.ext.JrubyEventExtLibrary;

/**
 * A pipeline execution "if" condition, compiled from the {@link BooleanExpression} of an
 * {@link org.logstash.config.ir.graph.IfVertex}.
 */
public interface EventCondition {

    /**
     * Checks if {@link org.logstash.ext.JrubyEventExtLibrary.RubyEvent} fulfils the condition.
     * @param event org.logstash.ext.RubyEvent to check
     * @return True iff event fulfils condition
     */
    boolean fulfilled(JrubyEventExtLibrary.RubyEvent event);

    /**
     * <h2>EventCondition Compiler.</h2>
     * Compiles {@link BooleanExpression} into {@link EventCondition} globally ensuring that no
     * duplicate {@link EventCondition} are generated by strict synchronization on the internal
     * compiler cache {@link EventCondition.Compiler#cache}.
     */
    final class Compiler {

        private static final Predicate<Integer> LESS_THAN = i -> i < 0;

        private static final Predicate<Integer> LESS_OR_EQUAL_THAN = i -> i <= 0;

        private static final Predicate<Integer> GREATER_THAN = i -> i > 0;

        private static final Predicate<Integer> GREATER_OR_EQUAL_THAN = i -> i >= 0;

        /**
         * Cache of all compiled {@link EventCondition}.
         */
        private final Map<String, EventCondition> cache = new HashMap<>(10);

        public Compiler() {
            //Utility Class.
        }

        /**
         * Compiles a {@link BooleanExpression} into an {@link EventCondition}.
         * All compilation is globally {@code synchronized} on {@link EventCondition.Compiler#cache}
         * to minimize code size by avoiding compiling logically equivalent expressions in more than
         * one instance.
         *
         * @param expression BooleanExpress to compile
         * @return Compiled {@link EventCondition}
         */
        public EventCondition buildCondition(final BooleanExpression expression) {
            synchronized (cache) {
                final String cachekey = expression.toRubyString();
                final EventCondition cached = cache.get(cachekey);
                if (cached != null) {
                    return cached;
                }
                final EventCondition condition;
                if (expression instanceof Eq) {
                    condition = eq((Eq) expression);
                } else if (expression instanceof RegexEq) {
                    condition = regex((RegexEq) expression);
                } else if (expression instanceof In) {
                    condition = in((In) expression);
                } else if (expression instanceof Or || expression instanceof And) {
                    condition = booleanCondition((BinaryBooleanExpression) expression);
                } else if (expression instanceof Truthy) {
                    condition = truthy((Truthy) expression);
                } else if (expression instanceof Not) {
                    condition = not((Not) expression);
                } else if (expression instanceof Gt || expression instanceof Gte
                        || expression instanceof Lt || expression instanceof Lte) {
                    condition = comparison((BinaryBooleanExpression) expression);
                } else if (expression instanceof Neq) {
                    condition = not(eq((BinaryBooleanExpression) expression));
                } else {
                    throw new EventCondition.Compiler.UnexpectedTypeException(expression);
                }
                cache.put(cachekey, condition);
                return condition;
            }
        }

        private EventCondition booleanCondition(final BinaryBooleanExpression expression) {
            final Expression left = expression.getLeft();
            final Expression right = expression.getRight();
            final EventCondition first;
            final EventCondition second;
            if (left instanceof BooleanExpression && right instanceof BooleanExpression) {
                first = buildCondition((BooleanExpression) left);
                second = buildCondition((BooleanExpression) right);
            } else if (eAndE(expression)) {
                first = truthy((EventValueExpression) left);
                second = truthy((EventValueExpression) right);
            } else if (left instanceof BooleanExpression && right instanceof EventValueExpression) {
                first = buildCondition((BooleanExpression) left);
                second = truthy((EventValueExpression) right);
            } else if (right instanceof BooleanExpression &&
                    left instanceof EventValueExpression) {
                first = truthy((EventValueExpression) left);
                second = buildCondition((BooleanExpression) right);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
            }
            if (expression instanceof And) {
                return event -> first.fulfilled(event) && second.fulfilled(event);
            } else if (expression instanceof Or) {
                return event -> first.fulfilled(event) || second.fulfilled(event);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(expression);
            }
        }

        private EventCondition not(final Not not) {
            final EventCondition condition;
            final Expression inner = not.getExpression();
            if (inner instanceof BooleanExpression) {
                condition = not(buildCondition((BooleanExpression) inner));
            } else if (inner instanceof EventValueExpression) {
                condition = not(truthy((EventValueExpression) inner));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(inner);
            }
            return condition;
        }

        /**
         * Checks if a {@link BinaryBooleanExpression} consists of a {@link ValueExpression} on the
         * left and a {@link EventValueExpression} on the right.
         *
         * @param expression Expression to check type for
         * @return True if the left branch of the {@link BinaryBooleanExpression} is a
         * {@link ValueExpression} and its right side is a {@link EventValueExpression}.
         */
        private static boolean vAndE(final BinaryBooleanExpression expression) {
            return expression.getLeft() instanceof ValueExpression &&
                    expression.getRight() instanceof EventValueExpression;
        }

        private static boolean vAndV(final BinaryBooleanExpression expression) {
            return expression.getLeft() instanceof ValueExpression &&
                    expression.getRight() instanceof ValueExpression;
        }

        private static boolean eAndV(final BinaryBooleanExpression expression) {
            return expression.getLeft() instanceof EventValueExpression &&
                    expression.getRight() instanceof ValueExpression;
        }

        private static boolean eAndE(final BinaryBooleanExpression expression) {
            return expression.getLeft() instanceof EventValueExpression &&
                    expression.getRight() instanceof EventValueExpression;
        }

        private static boolean vAndR(final BinaryBooleanExpression expression) {
            return expression.getLeft() instanceof ValueExpression &&
                    expression.getRight() instanceof RegexValueExpression;
        }

        private static EventCondition truthy(final Truthy truthy) {
            final EventCondition condition;
            final Expression inner = truthy.getExpression();
            if (inner instanceof EventValueExpression) {
                condition = truthy((EventValueExpression) inner);
            } else if (inner instanceof ValueExpression) {
                condition = constant(valueIsTruthy(((ValueExpression) inner).get()));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(inner);
            }
            return condition;
        }

        private static EventCondition regex(final RegexEq regex) {
            final EventCondition condition;
            final Expression uleft = regex.getLeft();
            final Expression uright = regex.getRight();
            if (eAndV(regex)) {
                condition = new EventCondition.Compiler.FieldMatches(
                        ((EventValueExpression) uleft).getFieldName(),
                        ((ValueExpression) uright).get().toString()
                );
            } else if (vAndR(regex)) {
                condition = new EventCondition.Compiler.ConstantMatches(
                        ((ValueExpression) uleft).get(),
                        ((RegexValueExpression) uright).get().toString()
                );
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition comparison(final BinaryBooleanExpression expression) {
            final Predicate<Integer> conditional;
            final Predicate<Integer> converse;
            if (expression instanceof Gte) {
                conditional = GREATER_OR_EQUAL_THAN;
                converse = LESS_OR_EQUAL_THAN;
            } else if (expression instanceof Lte) {
                conditional = LESS_OR_EQUAL_THAN;
                converse = GREATER_OR_EQUAL_THAN;
            } else if (expression instanceof Lt) {
                conditional = LESS_THAN;
                converse = GREATER_THAN;
            } else if (expression instanceof Gt) {
                conditional = GREATER_THAN;
                converse = LESS_THAN;
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(expression);
            }
            final EventCondition condition;
            final Expression uleft = expression.getLeft();
            final Expression uright = expression.getRight();
            if (eAndV(expression)) {
                condition = compareFieldToConstant(
                        (EventValueExpression) uleft, (ValueExpression) uright, conditional
                );
            } else if (vAndE(expression)) {
                condition = compareFieldToConstant(
                        (EventValueExpression) uright, (ValueExpression) uleft, converse
                );
            } else if (vAndV(expression)) {
                return compareConstants(
                        (ValueExpression) uleft, (ValueExpression) uright, conditional
                );
            } else {
                return compareFields(
                        (EventValueExpression) uleft, (EventValueExpression) uright, conditional
                );
            }
            return condition;
        }

        private static EventCondition in(final In in) {
            final Expression left = in.getLeft();
            final Expression right = in.getRight();
            final EventCondition condition;
            if (eAndV(in) && isScalar((ValueExpression) in.getRight())) {
                condition = new EventCondition.Compiler.FieldInConstantScalar(
                        FieldReference.from(((EventValueExpression) left).getFieldName()),
                        ((ValueExpression) right).get().toString()
                );
            } else if (vAndE(in) && isScalar((ValueExpression) in.getLeft())) {
                final Object leftv = ((ValueExpression) left).get();
                final FieldReference rfield =
                        FieldReference.from(((EventValueExpression) right).getFieldName());
                if (leftv instanceof String) {
                    condition = new EventCondition.Compiler.ConstantStringInField(
                            rfield, (String) leftv
                    );
                } else {
                    condition = new EventCondition.Compiler.ConstantScalarInField(rfield, leftv);
                }
            } else if (eAndV(in) && listValueRight(in)) {
                condition = in(
                        (EventValueExpression) left, (List<?>) ((ValueExpression) right).get()
                );
            } else if (eAndE(in)) {
                condition = in((EventValueExpression) left, (EventValueExpression) right);
            } else if (vAndV(in)) {
                condition = in((ValueExpression) left, (ValueExpression) right);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
            }
            return condition;
        }

        private static EventCondition in(final EventValueExpression left, final List<?> right) {
            return new EventCondition.Compiler.FieldInConstantList(
                    FieldReference.from(left.getFieldName()), right
            );
        }

        /**
         * Compiles a constant (due to both of its sides being constant {@link ValueExpression})
         * conditional.
         *
         * @param left  Constant left side {@link ValueExpression}
         * @param right Constant right side {@link ValueExpression}
         * @return Constant {@link EventCondition}
         */
        private static EventCondition in(final ValueExpression left, final ValueExpression right) {
            final Object found = right.get();
            final Object other = left.get();
            final boolean res;
            if (found instanceof ConvertedList && other instanceof RubyString) {
                res = ((ConvertedList) found).stream().anyMatch(item -> item.toString()
                        .equals(other.toString()));
            } else if (found instanceof RubyString && other instanceof RubyString) {
                res = found.toString().contains(other.toString());
            } else if (found instanceof RubyString && other instanceof ConvertedList) {
                res = ((ConvertedList) other).stream()
                        .anyMatch(item -> item.toString().equals(found.toString()));
            } else {
                res = found != null && found.equals(other);
            }
            return constant(res);
        }

        private static boolean listValueRight(final In in) {
            return ((ValueExpression) in.getRight()).get() instanceof List;
        }

        private static boolean isScalar(final ValueExpression expression) {
            final Object value = expression.get();
            return value instanceof String || value instanceof Number;
        }

        private static EventCondition in(final EventValueExpression left,
                                         final EventValueExpression right) {
            return new EventCondition.Compiler.FieldInField(
                    FieldReference.from(left.getFieldName()), FieldReference.from(right.getFieldName())
            );
        }

        @SuppressWarnings("unchecked")
        private static EventCondition eq(final EventValueExpression evalE,
                                         final ValueExpression valE) {
            return rubyFieldEquals(
                    (Comparable<IRubyObject>) Rubyfier.deep(RubyUtil.RUBY, valE.get()),
                    evalE.getFieldName()
            );
        }

        private static EventCondition eq(final BinaryBooleanExpression equals) {
            final Expression left = equals.getLeft();
            final Expression right = equals.getRight();
            final EventCondition condition;
            if (eAndV(equals)) {
                condition = eq((EventValueExpression) left, (ValueExpression) right);
            } else if (vAndE(equals)) {
                condition = eq((EventValueExpression) right, (ValueExpression) left);
            } else if (eAndE(equals)) {
                condition = eq((EventValueExpression) left, (EventValueExpression) right);
            } else {
                condition = constant(
                        ((ValueExpression) left).get().equals(((ValueExpression) right).get())
                );
            }
            return condition;
        }

        private static EventCondition eq(final EventValueExpression first,
                                         final EventValueExpression second) {
            final FieldReference field1 = FieldReference.from(first.getFieldName());
            final FieldReference field2 = FieldReference.from(second.getFieldName());
            return event -> {
                Event java = event.getEvent();
                return Objects.equals(
                        java.getUnconvertedField(field1),
                        java.getUnconvertedField(field2));
            };
        }

        private static EventCondition truthy(final EventValueExpression evalE) {
            return new EventCondition.Compiler.FieldTruthy(FieldReference.from(evalE.getFieldName()));
        }

        private static EventCondition not(final EventCondition condition) {
            return event -> !condition.fulfilled(event);
        }

        private static EventCondition compareConstants(final ValueExpression left,
                                                       final ValueExpression right, final Predicate<Integer> operator) {
            return constant(operator.test(compare(left.get(), right.get())));
        }

        private static EventCondition compareFields(final EventValueExpression left,
                                                    final EventValueExpression right, final Predicate<Integer> operator) {
            return event ->
                    operator.test(compare(mandatoryObjectFromValueExpression(left, event.getEvent()),
                                          mandatoryObjectFromValueExpression(right, event.getEvent())));
        }

        private static Object mandatoryObjectFromValueExpression(EventValueExpression valueExpression, Event event) {
            FieldReference fieldReference = FieldReference.from(valueExpression.getFieldName());
            Object object = event.getUnconvertedField(fieldReference);
            if (object == null){
                throw new IllegalStateException(
                        String.format("Line:%d, Column:%d: Invalid comparison - Field reference %s not in event",
                                      valueExpression.getSourceWithMetadata().getLine(),
                                      valueExpression.getSourceWithMetadata().getColumn(),
                                      valueExpression.getFieldName()));
            }
            return object;
        }

        @SuppressWarnings("unchecked")
        private static EventCondition compareFieldToConstant(final EventValueExpression left,
                                                             final ValueExpression right, final Predicate<Integer> operator) {
            final Comparable<IRubyObject> other =
                    (Comparable<IRubyObject>) Rubyfier.deep(RubyUtil.RUBY, right.get());
            return event ->
                 operator.test(compare(mandatoryObjectFromValueExpression(left, event.getEvent()), other));
        }

        @SuppressWarnings("unchecked")
        private static int compare(final Object left, final Object right) {
            if (left instanceof Comparable<?>) {
                return ((Comparable) left).compareTo(right);
            }
            throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
        }

        /**
         * Contains function using Ruby equivalent comparison logic.
         *
         * @param list  List to find value in
         * @param value Value to find in list
         * @return True iff value is in list
         */
        private static boolean contains(final ConvertedList list, final Object value) {
            for (final Object element : list) {
                if (value.equals(element)) {
                    return true;
                }
            }
            return false;
        }

        private static EventCondition rubyFieldEquals(final Comparable<IRubyObject> left,
                                                      final String field) {
            final FieldReference reference = FieldReference.from(field);
            return event ->
                    left.equals(Rubyfier.deep(RubyUtil.RUBY, event.getEvent().getUnconvertedField(reference)));
        }

        private static EventCondition constant(final boolean value) {
            return value ? event -> true : event -> false;
        }

        private static boolean valueIsTruthy(Object object) {
            if (object == null) {
                return false;
            }
            final String other = object.toString();
            return other != null && !other.isEmpty() &&
                    !Boolean.toString(false).equals(other);
        }

        private static RubyRegexp newRegexp(String pattern) {
            final Ruby runtime = RubyUtil.RUBY;
            return RubyRegexp.newRegexpFromStr(runtime, runtime.newString(pattern), 0);
        }

        private static boolean matches(RubyString str, RubyRegexp regexp) {
            return regexp.match_p(RubyUtil.RUBY.getCurrentContext(), str).isTrue(); // match? returns true/false
        }

        private static final class FieldMatches implements EventCondition {

            private final FieldReference field;

            private final RubyRegexp regexp;

            private FieldMatches(final String field, final String pattern) {
                this.field = FieldReference.from(field);
                this.regexp = newRegexp(pattern);
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object toMatch = event.getEvent().getUnconvertedField(field);
                return toMatch instanceof RubyString && matches((RubyString) toMatch, regexp);
            }
        }

        private static final class ConstantMatches implements EventCondition {

            private final boolean matches;

            private ConstantMatches(final Object constant, final String pattern) {
                this.matches = constant instanceof String &&
                        matches(RubyUtil.RUBY.newString((String) constant), newRegexp(pattern));
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return matches;
            }

        }

        private static final class ConstantStringInField implements EventCondition {

            private final FieldReference field;

            private final ByteList bytes;

            private final RubyString string;

            private ConstantStringInField(final FieldReference field, final String value) {
                this.field = field;
                this.string = RubyUtil.RUBY.newString(value);
                bytes = string.getByteList();
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                return found instanceof RubyString &&
                        ((RubyString) found).getByteList().indexOf(bytes) > -1
                        || found instanceof ConvertedList && contains((ConvertedList) found, string);
            }
        }

        private static final class ConstantScalarInField implements EventCondition {

            private final FieldReference field;

            private final Object value;

            private ConstantScalarInField(final FieldReference field, final Object value) {
                this.field = field;
                this.value = Valuefier.convert(value);
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                return found instanceof ConvertedList && contains((ConvertedList) found, value)
                        || Objects.equals(found, field);
            }
        }

        private static final class FieldInConstantScalar implements EventCondition {

            private final FieldReference field;

            private final ByteList value;

            private FieldInConstantScalar(final FieldReference field, final String value) {
                this.field = field;
                this.value = RubyUtil.RUBY.newString(value).getByteList();
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                return found instanceof RubyString &&
                        value.indexOf(((RubyString) found).getByteList()) > -1;
            }
        }

        private static final class FieldInField implements EventCondition {

            private final FieldReference left;

            private final FieldReference right;

            private FieldInField(final FieldReference left, final FieldReference right) {
                this.left = left;
                this.right = right;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object lfound = event.getEvent().getUnconvertedField(left);
                final Object rfound = event.getEvent().getUnconvertedField(right);
                if (lfound instanceof ConvertedList || lfound instanceof ConvertedMap) {
                    return false;
                } else if (lfound instanceof RubyString && rfound instanceof RubyString) {
                    return ((RubyString) rfound).getByteList()
                            .indexOf(((RubyString) lfound).getByteList()) > -1;
                } else if (rfound instanceof ConvertedList) {
                    return contains((ConvertedList) rfound, lfound);
                } else {
                    return lfound != null && lfound.equals(rfound);
                }
            }
        }

        private static final class FieldInConstantList implements EventCondition {

            private final FieldReference field;

            private final List<?> value;

            private FieldInConstantList(final FieldReference field, final List<?> value) {
                this.field = field;
                this.value = value;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                return found != null &&
                        value.stream().anyMatch(val -> val.toString().equals(found.toString()));
            }
        }

        private static final class FieldTruthy implements EventCondition {

            private final FieldReference field;

            private FieldTruthy(final FieldReference field) {
                this.field = field;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object object = event.getEvent().getUnconvertedField(field);
                return valueIsTruthy(object);
            }
        }

        /**
         * This {@link IllegalArgumentException} is thrown when the inputs to an {@code if}
         * condition do not conform to the expected types. It being thrown is a bug in Logstash
         * in every case.
         */
        private static final class UnexpectedTypeException extends IllegalArgumentException {

            private static final long serialVersionUID = 1L;

            UnexpectedTypeException(final Expression left, final Expression right) {
                super(
                        String.format(
                                "Unexpected input types left: %s, right: %s", getUnexpectedTypeDetails(left), getUnexpectedTypeDetails(right)
                        )
                );
            }

            UnexpectedTypeException(final Object inner) {
                super(String.format("Unexpected input type %s", getUnexpectedTypeDetails(inner)));
            }

            UnexpectedTypeException(final Object left, final Object right) {
                super(
                        String.format(
                                "Unexpected input type combination left %s, right %s", getUnexpectedTypeDetails(left), getUnexpectedTypeDetails(right)
                        )
                );
            }

            private static String getUnexpectedTypeDetails(Object unexpected) {
                String details;
                if (unexpected instanceof Expression) {
                    Expression expression = (Expression)unexpected;
                    details = (expression.getSourceWithMetadata() != null) ? expression.getSourceWithMetadata().toString()
                                                                           : expression.toString();
                } else {
                    if (unexpected == null){
                        return "null";
                    }
                    details = unexpected.toString();
                }
                return String.format("%s:%s", unexpected.getClass(), details);
            }
        }
    }
}
