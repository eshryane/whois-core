package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.ip.Ipv4Resource;
import net.ripe.db.whois.common.ip.Ipv6Resource;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.attrs.AddressPrefixRange;
import net.ripe.db.whois.common.rpsl.attrs.RangeOperation;

public class MembersSyntax implements AttributeSyntax {
    public static final AttributeSyntax MEMBERS_SYNTAX = new MembersSyntax(false);

    public static final AttributeSyntax MP_MEMBERS_SYNTAX = new MembersSyntax(true);

    private final boolean allowIpv6;

    MembersSyntax(final boolean allowIpv6) {
        this.allowIpv6 = allowIpv6;
    }

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case AS_SET:
                final boolean asNumberSyntax = AttributeSyntaxParser.AS_NUMBER_SYNTAX.matches(objectType, value);
                final boolean asSetSyntax = AttributeSyntaxParser.AS_SET_SYNTAX.matches(objectType, value);

                return asNumberSyntax || asSetSyntax;

            case ROUTE_SET:
                if (AttributeSyntaxParser.ROUTE_SET_SYNTAX.matches(objectType, value)) {
                    return true;
                }

                if (AttributeSyntaxParser.AS_NUMBER_SYNTAX.matches(objectType, value) || AttributeSyntaxParser.AS_SET_SYNTAX.matches(objectType, value)) {
                    return true;
                }

                if (AttributeSyntaxParser.ADDRESS_PREFIX_RANGE_SYNTAX.matches(objectType, value)) {
                    final AddressPrefixRange apr = AddressPrefixRange.parse(value);
                    if ((apr.getIpInterval() instanceof Ipv4Resource) || (allowIpv6 && apr.getIpInterval() instanceof Ipv6Resource)) {
                        return true;
                    }
                }

                return validateRouteSetWithRange(objectType, value);

            case RTR_SET:
                return allowIpv6 && AttributeSyntaxParser.IPV6_SYNTAX.matches(objectType, value) ||
                        AttributeSyntaxRegexp.INET_RTR_SYNTAX.matches(objectType, value) ||
                        AttributeSyntaxParser.RTR_SET_SYNTAX.matches(objectType, value) ||
                        AttributeSyntaxParser.IPV4_SYNTAX.matches(objectType, value);

            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        switch (objectType) {
            case AS_SET:
                return "" +
                        "list of\n" +
                        "<as-number> or\n" +
                        "<as-set-name>\n";
            case ROUTE_SET:
                if (allowIpv6) {
                    return "" +
                            "list of\n" +
                            "<address-prefix-range> or\n" +
                            "<route-set-name> or\n" +
                            "<route-set-name><range-operator>.\n";
                } else {
                    return "" +
                            "list of\n" +
                            "<ipv4-address-prefix-range> or\n" +
                            "<route-set-name> or\n" +
                            "<route-set-name><range-operator>.\n";
                }

            case RTR_SET:
                return allowIpv6 ? "" +
                        "list of\n" +
                        "<inet-rtr-name> or\n" +
                        "<rtr-set-name> or\n" +
                        "<ipv4-address> or\n" +
                        "<ipv6-address>\n"
                        : "" +
                        "list of\n" +
                        "<inet-rtr-name> or\n" +
                        "<rtr-set-name> or\n" +
                        "<ipv4-address>\n";

            default:
                return "";
        }
    }

    private boolean validateRouteSetWithRange(ObjectType objectType, String value) {
        final int rangeOperationIdx = value.lastIndexOf('^');
        if (rangeOperationIdx == -1) {
            return false;
        }

        final String routeSet = value.substring(0, rangeOperationIdx);
        final boolean routeSetSyntaxResult = AttributeSyntaxParser.ROUTE_SET_SYNTAX.matches(objectType, routeSet);
        if (!routeSetSyntaxResult) {
            return routeSetSyntaxResult;
        }

        final String rangeOperation = value.substring(rangeOperationIdx);
        try {
            RangeOperation.parse(rangeOperation, 0, 128);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}