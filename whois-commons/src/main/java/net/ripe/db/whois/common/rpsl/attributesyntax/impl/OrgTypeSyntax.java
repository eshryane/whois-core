package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.attrs.OrgType;

public class OrgTypeSyntax implements AttributeSyntax {

    public static final AttributeSyntax ORG_TYPE_SYNTAX = new OrgTypeSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        return OrgType.getFor(value) != null;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        final StringBuilder builder = new StringBuilder();
        builder.append("org-type can have one of these values:\n\n");

        for (final OrgType orgType : OrgType.values()) {
            builder.append("o '")
                    .append(orgType)
                    .append("' ")
                    .append(orgType.getInfo())
                    .append("\n");
        }

        builder.append("\n");
        return builder.toString();
    }
}