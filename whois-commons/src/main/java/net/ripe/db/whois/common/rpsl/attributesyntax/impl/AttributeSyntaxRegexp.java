package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

import java.util.regex.Pattern;

public class AttributeSyntaxRegexp implements AttributeSyntax {
    public static final AttributeSyntax ALIAS_SYNTAX = new AttributeSyntaxRegexp(254,
            Pattern.compile("(?i)^[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
            "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
            "without trailing dot (\".\").  The total length should not exceed\n" +
            "254 characters (octets).\n"
    );



    public static final AttributeSyntax AUTH_SCHEME_SYNTAX = new AttributeSyntaxRegexp(
            Pattern.compile("(?i)^(MD5-PW \\$1\\$[A-Z0-9./]{1,8}\\$[A-Z0-9./]{22}|PGPKEY-[A-F0-9]{8}|X509-[1-9][0-9]{0,19}|AUTO-[1-9][0-9]*)$"), "" +
            "<auth-scheme> <scheme-info>       Description\n" +
            "\n" +
            "MD5-PW        encrypted           We strongly advise phrases longer\n" +
            "              password, produced  than 8 characters to be used,\n" +
            "              using the FreeBSD   avoiding the use of words or\n" +
            "              crypt_md5           combinations of words found in any\n" +
            "              algorithm           dictionary of any language.\n" +
            "\n" +
            "PGPKEY-<id>                       Strong scheme of authentication.\n" +
            "                                  <id> is the PGP key ID to be\n" +
            "                                  used for authentication. This string\n" +
            "                                  is the same one that is used in the\n" +
            "                                  corresponding key-cert object's\n" +
            "                                  \"key-cert:\" attribute.\n" +
            "\n" +
            "X509-<nnn>                        Strong scheme of authentication.\n" +
            "                                  <nnn> is the index number of the\n" +
            "                                  corresponding key-cert object's\n" +
            "                                  \"key-cert:\" attribute (X509-nnn).\n"
    );

    public static final AttributeSyntax COUNTRY_CODE_SYNTAX = new AttributeSyntaxRegexp(Pattern.compile("(?i)^[a-z]{2}$"),
            "Valid two-letter ISO 3166 country code.");

    public static final AttributeSyntax EMAIL_SYNTAX = new AttributeSyntaxRegexp(80, Pattern.compile("(?i)^.+@([^.]+[.])+[^.]+$"),
            "An e-mail address as defined in RFC 2822.\n");

    public static final AttributeSyntax FREE_FORM_SYNTAX = new AttributeSyntaxRegexp(Pattern.compile("(?s)^.*$"), "" +
            "A sequence of ASCII characters.\n");

    public static final AttributeSyntax INET_RTR_SYNTAX = new AttributeSyntaxRegexp(254,
            Pattern.compile("(?i)^[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
            "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
            "without trailing dot (\".\").  The total length should not exceed\n" +
            "254 characters (octets).\n"
    );

    public static final AttributeSyntax IRT_SYNTAX = new AttributeSyntaxRegexp(Pattern.compile("(?i)^irt-[A-Z0-9_-]*[A-Z0-9]$"), "" +
            "An irt name is made up of letters, digits, the character\n" +
            "underscore \"_\", and the character hyphen \"-\"; it must start\n" +
            "with \"irt-\", and the last character of a name must be a\n" +
            "letter or a digit.\n");

    public static final AttributeSyntax KEY_CERT_SYNTAX = new AttributeSyntaxRegexp(
            Pattern.compile("(?i)^(PGPKEY-[A-F0-9]{8})|(X509-[1-9][0-9]*)|(AUTO-[1-9][0-9]*)$"), "" +
            "PGPKEY-<id>\n" +
            "\n" +
            "<id> is  the PGP key ID of the public key in 8-digit\n" +
            "hexadecimal format without \"0x\" prefix."
    );

    public static final AttributeSyntax LANGUAGE_CODE_SYNTAX = new AttributeSyntaxRegexp(Pattern.compile("(?i)^[a-z]{2}$"), "" +
            "Valid two-letter ISO 639-1 language code.\n");
    public static final AttributeSyntax NETNAME_SYNTAX = new AttributeSyntaxRegexp(80, Pattern.compile("(?i)^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$"), "" +
            "Made up of letters, digits, the character underscore \"_\",\n" +
            "and the character hyphen \"-\"; the first character of a name\n" +
            "must be a letter, and the last character of a name must be a\n" +
            "letter or a digit.\n");

    public static final AttributeSyntax NIC_HANDLE_SYNTAX = new AttributeSyntaxRegexp(30, Pattern.compile("(?i)^([A-Z]{2,4}([1-9][0-9]{0,5})?(-[A-Z]{2,10})?|AUTO-[1-9][0-9]*([A-Z]{2,4})?)$"), "" +
            "From 2 to 4 characters optionally followed by up to 6 digits\n" +
            "optionally followed by a source specification.  The first digit\n" +
            "must not be \"0\".  Source specification starts with \"-\" followed\n" +
            "by source name up to 9-character length.\n");


    public static final AttributeSyntax NUMBER_SYNTAX = new AttributeSyntaxRegexp(Pattern.compile("^[0-9]+$"), "" +
            "Specifies a numeric value.\n");

    public static final AttributeSyntax SOURCE_SYNTAX = new AttributeSyntaxRegexp(80,
            Pattern.compile("(?i)^[A-Z][A-Z0-9_-]*[A-Z0-9]$"), "" +
            "Made up of letters, digits, the character underscore \"_\",\n" +
            "and the character hyphen \"-\"; the first character of a\n" +
            "registry name must be a letter, and the last character of a\n" +
            "registry name must be a letter or a digit."
    );

    public static final AttributeSyntax ORGANISATION_SYNTAX = new AttributeSyntaxRegexp(30,
            Pattern.compile("(?i)^(ORG-[A-Z]{2,4}([1-9][0-9]{0,5})?-[A-Z][A-Z0-9_-]*[A-Z0-9]|AUTO-[1-9][0-9]*([A-Z]{2,4})?)$"), "" +
            "The 'ORG-' string followed by 2 to 4 characters, followed by up to 5 digits\n" +
            "followed by a source specification.  The first digit must not be \"0\".\n" +
            "Source specification starts with \"-\" followed by source name up to\n" +
            "9-character length.\n"
    );

    public static final AttributeSyntax ORG_NAME_SYNTAX = new AttributeSyntaxRegexp(
            Pattern.compile("(?i)^[\\]\\[A-Z0-9._\"*()@,&:!'`+\\/-]{1,64}( [\\]\\[A-Z0-9._\"*()@,&:!'`+\\/-]{1,64}){0,29}$"), "" +
            "A list of 1 to 30 words separated by white space. A word is made up of letters, digits and the following characters:\n" +
            "][)(._\"*@,&:!'`+/-\n" +
            "A word may have up to 64 characters and is not case sensitive. Each word can have any combination of the above characters with no restriction on the start or end of a word.\n"
    );

    public static final AttributeSyntax POEM_SYNTAX = new AttributeSyntaxRegexp(80,
            Pattern.compile("(?i)^POEM-[A-Z0-9][A-Z0-9_-]*$"), "" +
            "POEM-<string>\n" +
            "\n" +
            "<string> can include alphanumeric characters, and \"_\" and\n" +
            "\"-\" characters.\n"
    );

    public static final AttributeSyntax POETIC_FORM_SYNTAX = new AttributeSyntaxRegexp(80,
            Pattern.compile("(?i)^FORM-[A-Z0-9][A-Z0-9_-]*$"), "" +
            "FORM-<string>\n" +
            "\n" +
            "<string> can include alphanumeric characters, and \"_\" and\n" +
            "\"-\" characters.\n"
    );


    public static final AttributeSyntax PHONE_SYNTAX = new AttributeSyntaxRegexp(30,
            Pattern.compile("" +
                    "(?i)^" +
                    "[+][0-9. -]+" +                   // "normal" phone numbers
                    "(?:[(][0-9. -]+[)][0-9. -]+)?" +  // a possible '(123)' at the end
                    "(?:ext[.][0-9. -]+)?" +           // a possible 'ext. 123' at the end
                    "$"), "" +
            "Contact telephone number. Can take one of the forms:\n" +
            "\n" +
            "'+' <integer-list>\n" +
            "'+' <integer-list> \"(\" <integer-list> \")\" <integer-list>\n" +
            "'+' <integer-list> ext. <integer list>\n" +
            "'+' <integer-list> \"(\" integer list \")\" <integer-list> ext. <integer-list>\n"
    );

    private final Integer maxLength;
    private final Pattern matchPattern;
    private final String description;

    AttributeSyntaxRegexp(final Pattern matchPattern, final String description) {
        this(null, matchPattern, description);
    }

    AttributeSyntaxRegexp(final Integer maxLength, final Pattern matchPattern, final String description) {
        this.maxLength = maxLength;
        this.matchPattern = matchPattern;
        this.description = description;
    }

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        final boolean lengthOk = maxLength == null || value.length() <= maxLength;
        final boolean matches = matchPattern.matcher(value).matches();

        return lengthOk && matches;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return description;
    }
}