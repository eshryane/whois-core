package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class RoutePrefixSyntax implements AttributeSyntax {

    public static final AttributeSyntax HOLES_SYNTAX = new RoutePrefixSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case ROUTE:
                return AttributeSyntaxParser.IPV4_SYNTAX.matches(objectType, value);
            case ROUTE6:
                return AttributeSyntaxParser.IPV6_SYNTAX.matches(objectType, value);
            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        switch (objectType) {
            case ROUTE:
                return "" +
                        "An address prefix is represented as an IPv4 address followed\n" +
                        "by the character slash \"/\" followed by an integer in the\n" +
                        "range from 0 to 32.  The following are valid address\n" +
                        "prefixes: 128.9.128.5/32, 128.9.0.0/16, 0.0.0.0/0; and the\n" +
                        "following address prefixes are invalid: 0/0, 128.9/16 since\n" +
                        "0 or 128.9 are not strings containing four integers.";
            case ROUTE6:
                return "" +
                        "<ipv6-address>/<prefix>";
            default:
                return "";
        }
    }
}