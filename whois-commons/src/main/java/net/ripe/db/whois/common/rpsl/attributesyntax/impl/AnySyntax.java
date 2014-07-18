package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

public class AnySyntax implements AttributeSyntax {
    public static final AttributeSyntax ANY_SYNTAX = new AnySyntax();

    public static final AttributeSyntax CERTIF_SYNTAX = new AnySyntax("" +
            "The value of the public key should be supplied either using\n" +
            "multiple \"certif:\" attributes, or in one \"certif:\"\n" +
            "attribute. In the first case, this is easily done by\n" +
            "exporting the key from your local key ring in ASCII armored\n" +
            "format and prepending each line of the key with the string\n" +
            "\"certif:\". In the second case, line continuation should be\n" +
            "used to represent an ASCII armored format of the key. All\n" +
            "the lines of the exported key must be included; also the\n" +
            "begin and end markers and the empty line which separates the\n" +
            "header from the key body.\n");

    public static final AttributeSyntax GENERATED_SYNTAX = new AnySyntax("" +
            "Attribute generated by server.");

    public static final AttributeSyntax MBRS_BY_REF_SYNTAX = new AnySyntax("" +
            "<mntner-name> | ANY\n");

    public static final AttributeSyntax METHOD_SYNTAX = new AnySyntax("" +
            "Currently, only PGP keys are supported.\n");

    private final String description;

    public AnySyntax() {
        this("");
    }

    public AnySyntax(final String description) {
        this.description = description;
    }

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        return true;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return description;
    }
}