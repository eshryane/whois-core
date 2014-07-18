package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.generated.InjectParser;
import net.ripe.db.whois.common.generated.InjectR6Parser;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class InjectSyntax implements AttributeSyntax {
    public static final AttributeSyntax INJECT_SYNTAX = new InjectSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case ROUTE:
                return new AttributeSyntaxParser(new InjectParser()).matches(objectType, value);

            case ROUTE6:
                return new AttributeSyntaxParser(new InjectR6Parser()).matches(objectType, value);

            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return "" +
                "[at <router-expression>]\n" +
                "[action <action>]\n" +
                "[upon <condition>]\n";
    }
}