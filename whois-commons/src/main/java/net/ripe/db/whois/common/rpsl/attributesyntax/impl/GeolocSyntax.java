package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GeolocSyntax implements AttributeSyntax {
    public static final AttributeSyntax GEOLOC_SYNTAX = new GeolocSyntax();

    private static final Pattern GEOLOC_PATTERN = Pattern.compile("^[+-]?(\\d*\\.?\\d+)\\s+[+-]?(\\d*\\.?\\d+)$");

    private static final double LATITUDE_RANGE = 90.0;
    private static final double LONGITUDE_RANGE = 180.0;

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        final Matcher matcher = GEOLOC_PATTERN.matcher(value);
        if (!matcher.matches()) {
            return false;
        }

        if (Double.compare(LATITUDE_RANGE, Double.parseDouble(matcher.group(1))) < 0) {
            return false;
        }

        if (Double.compare(LONGITUDE_RANGE, Double.parseDouble(matcher.group(2))) < 0) {
            return false;
        }

        return true;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return "" +
                "Location coordinates of the resource. Can take one of the following forms:\n" +
                "\n" +
                "[-90,90][-180,180]\n";
    }
}