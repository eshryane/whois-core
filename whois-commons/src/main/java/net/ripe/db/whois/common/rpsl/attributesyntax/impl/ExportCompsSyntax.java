package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.generated.FilterParser;
import net.ripe.db.whois.common.generated.V6FilterParser;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class ExportCompsSyntax implements AttributeSyntax {
    public static final AttributeSyntax EXPORT_COMPS_SYNTAX = new ExportCompsSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case ROUTE:
                return new AttributeSyntaxParser(new FilterParser()).matches(objectType, value);
            case ROUTE6:
                return new AttributeSyntaxParser(new V6FilterParser()).matches(objectType, value);
            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        switch (objectType) {
            case ROUTE:
                return "" +
                        "Logical expression which when applied to a set of routes\n" +
                        "returns a subset of these routes. Please refer to RFC 2622\n" +
                        "for more information.";
            case ROUTE6:
                return "" +
                        "Logical expression which when applied to a set of routes\n" +
                        "returns a subset of these routes. Please refer to RFC 2622\n" +
                        "and RPSLng I-D for more information.";
            default:
                return "";
        }
    }
}