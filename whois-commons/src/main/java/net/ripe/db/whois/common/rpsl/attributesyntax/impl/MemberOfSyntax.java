package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class MemberOfSyntax implements AttributeSyntax {
    public static final AttributeSyntax MEMBER_OF_SYNTAX = new MemberOfSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case AUT_NUM:
                return AttributeSyntaxParser.AS_SET_SYNTAX.matches(objectType, value);
            case ROUTE:
            case ROUTE6:
                return AttributeSyntaxParser.ROUTE_SET_SYNTAX.matches(objectType, value);
            case INET_RTR:
                return AttributeSyntaxParser.RTR_SET_SYNTAX.matches(objectType, value);
            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        switch (objectType) {
            case AUT_NUM:
                return "" +
                        "An as-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"as-\", and the last character of a name must\n" +
                        "be a letter or a digit.\n" +
                        "\n" +
                        "An as-set name can also be hierarchical.  A hierarchical set\n" +
                        "name is a sequence of set names and AS numbers separated by\n" +
                        "colons \":\".  At least one component of such a name must be\n" +
                        "an actual set name (i.e. start with \"as-\").  All the set\n" +
                        "name components of a hierarchical as-name have to be as-set\n" +
                        "names.\n";

            case ROUTE:
                return "" +
                        "An route-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"rs-\", and the last character of a name must\n" +
                        "be a letter or a digit.\n" +
                        "\n" +
                        "A route-set name can also be hierarchical.  A hierarchical\n" +
                        "set name is a sequence of set names and AS numbers separated\n" +
                        "by colons \":\".  At least one component of such a name must\n" +
                        "be an actual set name (i.e. start with \"rs-\").  All the set\n" +
                        "name components of a hierarchical route-name have to be\n" +
                        "route-set names.\n";

            case ROUTE6:
                return "" +
                        "An route-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"rs-\", and the last character of a name must\n" +
                        "be a letter or a digit.\n" +
                        "\n" +
                        "A route-set name can also be hierarchical.  A hierarchical\n" +
                        "set name is a sequence of set names and AS numbers separated\n" +
                        "by colons \":\".  At least one component of such a name must\n" +
                        "be an actual set name (i.e. start with \"rs-\").  All the set\n" +
                        "name components of a hierarchical route-name have to be\n" +
                        "route-set names.\n";

            case INET_RTR:
                return "" +
                        "A router-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"rtrs-\", and the last character of a name\n" +
                        "must be a letter or a digit.\n" +
                        "\n" +
                        "A router-set name can also be hierarchical.  A hierarchical\n" +
                        "set name is a sequence of set names and AS numbers separated\n" +
                        "by colons \":\".  At least one component of such a name must\n" +
                        "be an actual set name (i.e. start with \"rtrs-\").  All the\n" +
                        "set name components of a hierarchical router-set name have\n" +
                        "to be router-set names.\n";
            default:
                return "";
        }
    }
}