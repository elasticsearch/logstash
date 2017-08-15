package org.logstash.config.ir.compiler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.jruby.RubyString;
import org.logstash.ConvertedList;
import org.logstash.FieldReference;
import org.logstash.PathCache;
import org.logstash.RubyUtil;
import org.logstash.bivalues.BiValues;
import org.logstash.config.ir.expression.BinaryBooleanExpression;
import org.logstash.config.ir.expression.BooleanExpression;
import org.logstash.config.ir.expression.EventValueExpression;
import org.logstash.config.ir.expression.Expression;
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
import org.logstash.ext.JrubyEventExtLibrary;

/**
 * A pipeline execution "if" condition, compiled from the {@link BooleanExpression} of an
 * {@link org.logstash.config.ir.graph.IfVertex}.
 */
public interface EventCondition {

    /**
     * Checks if {@link JrubyEventExtLibrary.RubyEvent} fulfils the condition.
     * @param event RubyEvent to check
     * @return True iff event fulfils condition
     */
    boolean fulfilled(JrubyEventExtLibrary.RubyEvent event);

    /**
     * <h3>EventCondition Compiler.</h3>
     * Compiles {@link BooleanExpression} into {@link EventCondition} globally ensuring that no
     * duplicate {@link EventCondition} are generated by strict synchronization on the internal
     * compiler cache {@link EventCondition.Compiler#CACHE}.
     */
    final class Compiler {

        /**
         * {@link EventCondition} that is always {@code true}.
         */
        private static final EventCondition TRUE = event -> true;

        /**
         * {@link EventCondition} that is always {@code false}.
         */
        private static final EventCondition FALSE = event -> false;

        /**
         * Cache of all compiled {@link EventCondition}.
         */
        private static final Map<String, EventCondition> CACHE = new HashMap<>(10);

        private Compiler() {
            //Utility Class.
        }

        /**
         * Compiles a {@link BooleanExpression} into an {@link EventCondition}.
         * All compilation is globally {@code synchronized} on {@link EventCondition.Compiler#CACHE}
         * to minimize code size by avoiding compiling logically equivalent expressions in more than
         * one instance.
         * @param expression BooleanExpress to compile
         * @return Compiled {@link EventCondition}
         */
        public static EventCondition buildCondition(final BooleanExpression expression) {
            synchronized (CACHE) {
                final String cachekey = expression.toRubyString();
                final EventCondition cached = CACHE.get(cachekey);
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
                } else if (expression instanceof Or) {
                    condition = or(booleanPair((BinaryBooleanExpression) expression));
                } else if (expression instanceof Truthy) {
                    condition = truthy((Truthy) expression);
                } else if (expression instanceof Not) {
                    condition = not((Not) expression);
                } else if (expression instanceof Gt) {
                    condition = gt((Gt) expression);
                } else if (expression instanceof Gte) {
                    condition = gte((Gte) expression);
                } else if (expression instanceof Lt) {
                    condition = lt((Lt) expression);
                } else if (expression instanceof Lte) {
                    condition = lte((Lte) expression);
                } else if (expression instanceof And) {
                    condition = and(booleanPair((BinaryBooleanExpression) expression));
                } else if (expression instanceof Neq) {
                    condition = neq((Neq) expression);
                } else {
                    throw new EventCondition.Compiler.UnexpectedTypeException(expression);
                }
                CACHE.put(cachekey, condition);
                return condition;
            }
        }

        /**
         * Checks if a {@link BinaryBooleanExpression} consists of a {@link ValueExpression} on the
         * left and a {@link EventValueExpression} on the right.
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

        private static EventCondition neq(final Neq neq) {
            final EventCondition condition;
            final Expression uleft = neq.getLeft();
            final Expression uright = neq.getRight();
            if (eAndV(neq)) {
                condition = not(eq((EventValueExpression) uleft, (ValueExpression) uright));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition truthy(final Truthy truthy) {
            final EventCondition condition;
            final Expression inner = truthy.getExpression();
            if (inner instanceof EventValueExpression) {
                condition = truthy((EventValueExpression) inner);
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
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition not(final Not not) {
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

        private static EventCondition gte(final Gte gte) {
            final EventCondition condition;
            final Expression uleft = gte.getLeft();
            final Expression uright = gte.getRight();
            if (eAndV(gte)) {
                final EventValueExpression left = (EventValueExpression) uleft;
                final ValueExpression right = (ValueExpression) uright;
                condition = or(gt(left, right), eq(left, right));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition lte(final Lte lte) {
            final EventCondition condition;
            final Expression uleft = lte.getLeft();
            final Expression uright = lte.getRight();
            if (eAndV(lte)) {
                condition = not(gt((EventValueExpression) uleft, (ValueExpression) uright));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition lt(final Lt lt) {
            final EventCondition condition;
            final Expression uleft = lt.getLeft();
            final Expression uright = lt.getRight();
            if (eAndV(lt)) {
                final EventValueExpression left = (EventValueExpression) uleft;
                final ValueExpression right = (ValueExpression) uright;
                condition = not(or(gt(left, right), eq(left, right)));
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(uleft, uright);
            }
            return condition;
        }

        private static EventCondition in(final In in) {
            final Expression left = in.getLeft();
            final Expression right = in.getRight();
            final EventCondition condition;
            if (eAndV(in) && scalarValueRight(in)) {
                condition = new EventCondition.Compiler.FieldArrayContainsValue(
                    PathCache.cache(((EventValueExpression) left).getFieldName()),
                    ((ValueExpression) right).get().toString()
                );
            } else if (vAndE(in) && scalarValueLeft(in)) {
                condition = new EventCondition.Compiler.FieldArrayContainsValue(
                    PathCache.cache(((EventValueExpression) right).getFieldName()),
                    ((ValueExpression) left).get().toString()
                );
            } else if (eAndV(in) && listValueRight(in)) {
                condition = in(
                    (EventValueExpression) left, (List<?>) ((ValueExpression) right).get()
                );
            } else if (eAndE(in)) {
                condition = in((EventValueExpression) right, (EventValueExpression) left);
            } else if (vAndV(in)) {
                condition = in((ValueExpression) left, (ValueExpression) right);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
            }
            return condition;
        }

        private static EventCondition in(final EventValueExpression left, final List<?> right) {
            return new EventCondition.Compiler.FieldContainsListedValue(
                PathCache.cache(left.getFieldName()), right
            );
        }

        /**
         * Compiles a constant (due to both of its sides being constant {@link ValueExpression})
         * conditional into either {@link EventCondition.Compiler#TRUE} or
         * {@link EventCondition.Compiler#FALSE}.
         * @param left Constant left side {@link ValueExpression}
         * @param right Constant right side {@link ValueExpression}
         * @return Either {@link EventCondition.Compiler#TRUE} or
         * {@link EventCondition.Compiler#FALSE}
         */
        private static EventCondition in(final ValueExpression left, final ValueExpression right) {
            final Object found = right.get();
            final Object other = left.get();
            if (found instanceof ConvertedList && other instanceof RubyString) {
                return ((ConvertedList) found).stream().anyMatch(item -> item.toString()
                    .equals(other.toString())) ? TRUE : FALSE;
            } else if (found instanceof RubyString && other instanceof RubyString) {
                return found.toString().contains(other.toString()) ? TRUE : FALSE;
            } else if (found instanceof RubyString && other instanceof ConvertedList) {
                return ((ConvertedList) other).stream()
                    .anyMatch(item -> item.toString().equals(found.toString())) ? TRUE : FALSE;
            } else {
                return found != null && other != null && found.equals(other) ? TRUE : FALSE;
            }
        }

        private static boolean listValueRight(final In in) {
            return ((ValueExpression) in.getRight()).get() instanceof List;
        }

        private static boolean scalarValueRight(final In in) {
            return isScalar((ValueExpression) in.getRight());
        }

        private static boolean scalarValueLeft(final In in) {
            return isScalar((ValueExpression) in.getLeft());
        }

        private static boolean isScalar(final ValueExpression expression) {
            final Object value = expression.get();
            return value instanceof String || value instanceof Number;
        }

        private static EventCondition in(final EventValueExpression left,
            final EventValueExpression right) {
            return new EventCondition.Compiler.FieldArrayContainsFieldValue(
                PathCache.cache(left.getFieldName()), PathCache.cache(right.getFieldName())
            );
        }

        private static EventCondition eq(final EventValueExpression evale,
            final ValueExpression vale) {
            return new EventCondition.Compiler.FieldEquals(
                evale.getFieldName(), vale.get().toString()
            );
        }

        private static EventCondition eq(final Eq equals) {
            final Expression left = equals.getLeft();
            final Expression right = equals.getRight();
            final EventCondition condition;
            if (eAndV(equals)) {
                condition = eq((EventValueExpression) left, (ValueExpression) right);
            } else if (eAndE(equals)) {
                condition = eq((EventValueExpression) left, (EventValueExpression) right);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
            }
            return condition;
        }

        private static EventCondition eq(final EventValueExpression first,
            final EventValueExpression second) {
            return new EventCondition.Compiler.FieldEqualsField(
                PathCache.cache(first.getFieldName()), PathCache.cache(second.getFieldName())
            );
        }

        private static EventCondition gt(final Gt greater) {
            final EventCondition condition;
            final Expression left = greater.getLeft();
            final Expression right = greater.getRight();
            if (eAndV(greater)) {
                condition = gt((EventValueExpression) left, (ValueExpression) right);
            } else {
                throw new EventCondition.Compiler.UnexpectedTypeException(left, right);
            }
            return condition;
        }

        private static EventCondition gt(final EventValueExpression left,
            final ValueExpression right) {
            return new EventCondition.Compiler.FieldGreaterThan(
                left.getFieldName(), right.get().toString()
            );
        }

        private static EventCondition truthy(final EventValueExpression evale) {
            return new EventCondition.Compiler.FieldTruthy(PathCache.cache(evale.getFieldName()));
        }

        private static EventCondition[] booleanPair(final BinaryBooleanExpression expression) {
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
            return new EventCondition[]{first, second};
        }

        public static EventCondition not(final EventCondition condition) {
            return new EventCondition.Compiler.Negated(condition);
        }

        private static EventCondition or(final EventCondition... conditions) {
            return new EventCondition.Compiler.OrCondition(conditions[0], conditions[1]);
        }

        private static EventCondition and(final EventCondition... conditions) {
            return new EventCondition.Compiler.AndCondition(conditions[0], conditions[1]);
        }

        private static final class Negated implements EventCondition {

            private final EventCondition condition;

            Negated(final EventCondition condition) {
                this.condition = condition;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return !condition.fulfilled(event);
            }
        }

        private static final class AndCondition implements EventCondition {

            private final EventCondition first;

            private final EventCondition second;

            AndCondition(final EventCondition first, final EventCondition second) {
                this.first = first;
                this.second = second;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return first.fulfilled(event) && second.fulfilled(event);
            }
        }

        private static final class OrCondition implements EventCondition {

            private final EventCondition first;

            private final EventCondition second;

            OrCondition(final EventCondition first, final EventCondition second) {
                this.first = first;
                this.second = second;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return first.fulfilled(event) || second.fulfilled(event);
            }
        }

        private static final class FieldGreaterThan implements EventCondition {

            private final FieldReference field;

            private final RubyString value;

            private FieldGreaterThan(final String field, final String value) {
                this.field = PathCache.cache(field);
                this.value = RubyUtil.RUBY.newString(value);
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return value.toString()
                    .compareTo(event.getEvent().getUnconvertedField(field).toString()) < 0;
            }
        }

        private static final class FieldEquals implements EventCondition {

            private final FieldReference field;

            private final RubyString value;

            private FieldEquals(final String field, final String value) {
                this.field = PathCache.cache(field);
                this.value = RubyUtil.RUBY.newString(value);
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object val = event.getEvent().getUnconvertedField(field);
                return val != null && value.toString().equals(val.toString());
            }
        }

        private static final class FieldEqualsField implements EventCondition {

            private final FieldReference one;

            private final FieldReference other;

            private FieldEqualsField(final FieldReference one, final FieldReference other) {
                this.one = one;
                this.other = other;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                return event.getEvent().getUnconvertedField(one)
                    .equals(event.getEvent().getUnconvertedField(other));
            }
        }

        private static final class FieldMatches implements EventCondition {

            private final FieldReference field;

            private final Pattern value;

            private FieldMatches(final String field, final String value) {
                this.field = PathCache.cache(field);
                this.value = Pattern.compile(value);
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final String tomatch = event.getEvent().getUnconvertedField(field).toString();
                return value.matcher(tomatch).find();
            }
        }

        private static final class FieldArrayContainsValue implements EventCondition {

            private final FieldReference field;

            private final String value;

            private FieldArrayContainsValue(final FieldReference field, final String value) {
                this.field = field;
                this.value = value;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                if (found instanceof ConvertedList) {
                    return ((ConvertedList) found).stream().anyMatch(
                        item -> item.toString().equals(value)
                    );
                } else
                    return found != null && found.toString().contains(value);
            }
        }

        private static final class FieldArrayContainsFieldValue implements EventCondition {

            private final FieldReference field;

            private final FieldReference value;

            private FieldArrayContainsFieldValue(final FieldReference field,
                final FieldReference value) {
                this.field = field;
                this.value = value;
            }

            @Override
            public boolean fulfilled(final JrubyEventExtLibrary.RubyEvent event) {
                final Object found = event.getEvent().getUnconvertedField(field);
                final Object other = event.getEvent().getUnconvertedField(value);
                if (found instanceof ConvertedList && other instanceof RubyString) {
                    return ((ConvertedList) found).stream().anyMatch(
                        item -> item.toString().equals(other.toString())
                    );
                } else if (found instanceof RubyString && other instanceof RubyString) {
                    return found.toString().contains(other.toString());
                } else if (found instanceof RubyString && other instanceof ConvertedList) {
                    return ((ConvertedList) other).stream().anyMatch(
                        item -> item.toString().equals(found.toString())
                    );
                } else {
                    return found != null && other != null && found.equals(other);
                }
            }

            private static boolean contains(final ConvertedList list, final Object value) {
                if (value == null || value == BiValues.NULL_BI_VALUE) {
                    return list.contains(BiValues.NULL_BI_VALUE);
                }
                final String val = String.valueOf(value);
                for (final Object element : list) {
                    if (val.equals(element.toString())) {
                        return true;
                    }
                }
                return false;
            }
        }

        private static final class FieldContainsListedValue implements EventCondition {

            private final FieldReference field;

            private final List<?> value;

            private FieldContainsListedValue(final FieldReference field, final List<?> value) {
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
                if (object == null) {
                    return false;
                }
                final String other = object.toString();
                return other != null && !other.isEmpty() &&
                    !Boolean.toString(false).equals(other);
            }
        }

        /**
         * This {@link IllegalArgumentException} is thrown when the inputs to an {@code if}
         * condition do not conform to the expected types. It being thrown is a bug in Logstash
         * in every case.
         */
        private static final class UnexpectedTypeException extends IllegalArgumentException {

            private static final long serialVersionUID = -3673305675726770832L;

            UnexpectedTypeException(final Expression left, final Expression right) {
                super(
                    String.format("Unexpected input types %s %s", left.getClass(), right.getClass())
                );
            }

            UnexpectedTypeException(final Expression inner) {
                super(String.format("Unexpected input type %s", inner));
            }
        }
    }
}
