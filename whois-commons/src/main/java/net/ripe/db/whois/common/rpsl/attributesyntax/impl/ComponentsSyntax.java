package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.generated.ComponentsParser;
import net.ripe.db.whois.common.generated.ComponentsR6Parser;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class ComponentsSyntax implements AttributeSyntax {

    public static final AttributeSyntax COMPONENTS_SYNTAX = new ComponentsSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case ROUTE:
                return new AttributeSyntaxParser(new ComponentsParser()).matches(objectType, value);
            case ROUTE6:
                return new AttributeSyntaxParser(new ComponentsR6Parser()).matches(objectType, value);
            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return "" +
                "[ATOMIC] [[<filter>] [protocol <protocol> <filter> ...]]\n" +
                "\n" +
                "<protocol> is a routing routing protocol name such as\n" +
                "BGP4, OSPF or RIP\n" +
                "\n" +
                "<filter> is a policy expression\n";
    }
}