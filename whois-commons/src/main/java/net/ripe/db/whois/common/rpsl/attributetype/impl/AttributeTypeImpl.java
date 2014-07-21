package net.ripe.db.whois.common.rpsl.attributetype.impl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;

import javax.annotation.CheckForNull;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciString;
import static net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeValueType.LIST_VALUE;

/**
 * Created by michel on 7/18/14.
 */
public class AttributeTypeImpl implements AttributeType {

    private String name;
    private String flag;
    private Documented description;
    private AttributeSyntax syntax;
    private AttributeValueType valueType;
    private Set<ObjectType> references;

    private static final Map<CIString, AttributeType> TYPE_NAMES = Maps.newHashMap();

    private AttributeTypeImpl(String name, String flag, Documented description, AttributeSyntax syntax, AttributeValueType valueType, Set<ObjectType> references) {
        this.name = name;
        this.flag = flag;
        this.description = description;
        this.syntax = syntax;
        this.valueType = valueType;
        this.references = references;

        TYPE_NAMES.put(ciString(name), this);
    }

    protected AttributeTypeImpl(String name, String flag, String description, AttributeSyntax syntax, AttributeValueType valueType, Set<ObjectType> references) {
        this(name, flag, new Single(description), syntax, valueType, references);
    }


    protected AttributeTypeImpl(String name, String flag, String description, AttributeSyntax syntax, AttributeValueType valueType) {
        this(name, flag, new Single(description), syntax, valueType, null);
    }

    protected AttributeTypeImpl(String name, String flag, String description, AttributeSyntax syntax, Set<ObjectType> references) {
        this(name, flag, new Single(description), syntax, AttributeValueType.SINGLE_VALUE, references);
    }

    protected AttributeTypeImpl(String name, String flag, Documented description, AttributeSyntax syntax, Set<ObjectType> references) {
        this(name, flag, description, syntax, AttributeValueType.SINGLE_VALUE, references);
    }

    protected AttributeTypeImpl(String name, String flag, String description, AttributeSyntax syntax) {
        this(name, flag, new Single(description), syntax, AttributeValueType.SINGLE_VALUE, null);
    }

    protected AttributeTypeImpl(String name, String flag, Documented description, AttributeSyntax syntax) {
        this(name, flag, description, syntax, AttributeValueType.SINGLE_VALUE, null);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getFlag() {
        return flag;
    }

    @Override
    public boolean isListValue() {
        return valueType.equals(LIST_VALUE);
    }

    @Override
    public AttributeSyntax getSyntax() {
        return syntax;
    }

    @Override
    public boolean isValidValue(ObjectType objectType, CIString value) {
        return isValidValue(objectType, value.toString());
    }

    @Override
    public boolean isValidValue(ObjectType objectType, String value) {
        return syntax.matches(objectType, value);
    }

    @Override
    public Iterable<String> splitValue(String value) {
        return valueType.getValues(value);
    }

    @Override
    public Set<ObjectType> getReferences() {
        return references;
    }

    @Override
    public Set<ObjectType> getReferences(CIString value) {
        if (this.equals(AttributeTypes.AUTH) && (value.startsWith("md5-pw"))) {
            return Collections.emptySet();
        }

        return references;
    }

    @Override
    public String getDescription(ObjectType objectType) {
        return description.getDescription(objectType);
    }

    @Override
    public String toString() {
        return name;
    }

    protected static AttributeType getByName(final String name) throws IllegalArgumentException {
        final AttributeType attributeType = getByNameOrNull(name);
        if (attributeType == null) {
            throw new IllegalArgumentException("Attribute type " + name + " not found");
        }

        return attributeType;
    }

    @CheckForNull
    protected static AttributeType getByNameOrNull(final String name) {
        String nameOrNull = name;
        if (nameOrNull.length() == 3 && nameOrNull.charAt(0) == '*') {
            nameOrNull = nameOrNull.substring(1);
        }

        return TYPE_NAMES.get(ciString(nameOrNull));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AttributeTypeImpl that = (AttributeTypeImpl) o;

        if (description != null ? !description.equals(that.description) : that.description != null) return false;
        if (!flag.equals(that.flag)) return false;
        if (!name.equals(that.name)) return false;
        if (references != null ? !references.equals(that.references) : that.references != null) return false;
        if (syntax != null ? !syntax.equals(that.syntax) : that.syntax != null) return false;
        if (valueType != null ? !valueType.equals(that.valueType) : that.valueType != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + flag.hashCode();
        result = 31 * result + (description != null ? description.hashCode() : 0);
        result = 31 * result + (syntax != null ? syntax.hashCode() : 0);
        result = 31 * result + (valueType != null ? valueType.hashCode() : 0);
        result = 31 * result + (references != null ? references.hashCode() : 0);
        return result;
    }

    protected static Collection<AttributeType> values () {
        return TYPE_NAMES.values();
    }
}
