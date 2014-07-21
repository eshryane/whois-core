package net.ripe.db.whois.common.rpsl.attributetype;

import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

import java.util.Set;

/**
 * Created by michel on 7/18/14.
 */
public interface AttributeType extends Documented {
    public String getName();
    @Override
    public String toString();
    public String getFlag();
    boolean isListValue();
    public AttributeSyntax getSyntax();
    public boolean isValidValue(final ObjectType objectType, final CIString value);
    public boolean isValidValue(final ObjectType objectType, final String value);
    Iterable<String> splitValue(final String value);
    public Set<ObjectType> getReferences();
    public Set<ObjectType> getReferences(final CIString value);

}
