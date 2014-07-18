package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import com.google.common.base.Splitter;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

import java.util.regex.Pattern;

public class PersonRoleSyntax implements AttributeSyntax {
    public static final AttributeSyntax PERSON_ROLE_NAME_SYNTAX = new PersonRoleSyntax();

    private static final Pattern PATTERN = Pattern.compile("(?i)^[A-Z][A-Z0-9\\\\.`'_-]{0,63}(?: [A-Z0-9\\\\.`'_-]{1,64}){0,9}$");
    private static final Splitter SPLITTER = Splitter.on(' ').trimResults().omitEmptyStrings();

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        if (!PATTERN.matcher(value).matches()) {
            return false;
        }

        int nrNamesStartingWithLetter = 0;
        for (final String name : SPLITTER.split(value)) {
            if (Character.isLetter(name.charAt(0))) {
                nrNamesStartingWithLetter++;

                if (nrNamesStartingWithLetter == 2) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return "" +
                "It should contain 2 to 10 words.\n" +
                "Each word consists of letters, digits or the following symbols:\n" +
                ".`'_-\n" +
                "The first word should begin with a letter.\n" +
                "Max 64 characters can be used in each word.";
    }
}