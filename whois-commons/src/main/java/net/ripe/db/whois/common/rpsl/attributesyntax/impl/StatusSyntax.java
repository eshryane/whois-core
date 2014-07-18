package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.attrs.Inet6numStatus;
import net.ripe.db.whois.common.rpsl.attrs.InetnumStatus;

import static net.ripe.db.whois.common.domain.CIString.ciString;

public class StatusSyntax implements AttributeSyntax {

    public static final AttributeSyntax STATUS_SYNTAX = new StatusSyntax();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        switch (objectType) {
            case INETNUM:
                try {
                    InetnumStatus.getStatusFor(ciString(value));
                    return true;
                } catch (IllegalArgumentException ignored) {
                    return false;
                }
            case INET6NUM:
                try {
                    Inet6numStatus.getStatusFor(ciString(value));
                    return true;
                } catch (IllegalArgumentException ignored) {
                    return false;
                }
            default:
                return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        final StringBuilder descriptionBuilder = new StringBuilder();
        descriptionBuilder.append("Status can have one of these values:\n\n");

        switch (objectType) {
            case INETNUM:
                for (final InetnumStatus status : InetnumStatus.values()) {
                    descriptionBuilder.append("o ").append(status).append('\n');
                }

                return descriptionBuilder.toString();
            case INET6NUM:
                for (final Inet6numStatus status : Inet6numStatus.values()) {
                    descriptionBuilder.append("o ").append(status).append('\n');
                }

                return descriptionBuilder.toString();
            default:
                return "";
        }
    }
}