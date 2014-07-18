package net.ripe.db.whois.common.rpsl.attributesyntax.impl;

import net.ripe.db.whois.common.generated.*;
import net.ripe.db.whois.common.rpsl.AttributeParser;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributesyntax.AttributeSyntax;

import java.util.HashMap;

/**
 * Created by michel on 7/18/14.
 */
public class AttributeSyntaxParser implements AttributeSyntax {
    public static final AttributeSyntax AS_BLOCK_SYNTAX = new AttributeSyntaxParser(new AttributeParser.AsBlockParser(), "" +
            "<as-number> - <as-number>\n");

    public static final AttributeSyntax AS_NUMBER_SYNTAX = new AttributeSyntaxParser(new AttributeParser.AutNumParser(), "" +
            "An \"AS\" string followed by an integer in the range\n" +
            "from 0 to 4294967295\n");

    public static final AttributeSyntax AS_SET_SYNTAX = new AttributeSyntaxParser(new AttributeParser.AsSetParser(), "" +
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
            "names.\n");

    public static final AttributeSyntax AGGR_BNDRY_SYNTAX = new AttributeSyntaxParser(new AggrBndryParser(), "" +
            "[<as-expression>]\n");

    public static final AttributeSyntax AGGR_MTD_SYNTAX = new AttributeSyntaxParser(new AggrMtdParser(), "" +
            "inbound | outbound [<as-expression>]\n");

    public static final AttributeSyntax ADDRESS_PREFIX_RANGE_SYNTAX = new AttributeSyntaxParser(new AttributeParser.AddressPrefixRangeParser());

    public static final AttributeSyntax DEFAULT_SYNTAX = new AttributeSyntaxParser(new DefaultParser(), "" +
            "to <peering> [action <action>] [networks <filter>]");

    public static final AttributeSyntax CHANGED_SYNTAX = new AttributeSyntaxParser(new AttributeParser.ChangedParser(), "" +
            "An e-mail address as defined in RFC 2822, followed by a date\n" +
            "in the format YYYYMMDD.\n");

    public static final AttributeSyntax DOMAIN_SYNTAX = new AttributeSyntaxParser(new AttributeParser.DomainParser(), "" +
            "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
            "without trailing dot (\".\").  The total length should not exceed\n" +
            "254 characters (octets).\n");

    public static final AttributeSyntax DS_RDATA_SYNTAX = new AttributeSyntaxParser(new AttributeParser.DsRdataParser(), "" +
            "<Keytag> <Algorithm> <Digest type> <Digest>\n" +
            "\n" +
            "Keytag is represented by an unsigned decimal integer (0-65535).\n" +
            "\n" +
            "Algorithm is represented by an unsigned decimal integer (0-255).\n" +
            "\n" +
            "Digest type is represented by a unsigned decimal integer (0-255).\n" +
            "\n" +
            "Digest is a digest in hexadecimal representation (case insensitive). Its length varies for various digest types.\n" +
            "For digest type SHA-1 digest is represented by 20 octets (40 characters, plus possible spaces).\n" +
            "\n" +
            "For more details, see RFC4034.\n");

    public static final AttributeSyntax EXPORT_SYNTAX = new AttributeSyntaxParser(new ExportParser(), "" +
            "[protocol <protocol-1>] [into <protocol-1>]\n" +
            "to <peering-1> [action <action-1>]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "to <peering-N> [action <action-N>]\n" +
            "announce <filter>\n");

    public static final AttributeSyntax FILTER_SYNTAX = new AttributeSyntaxParser(new FilterParser(), "" +
            "Logical expression which when applied to a set of routes\n" +
            "returns a subset of these routes. Please refer to RFC 2622\n" +
            "for more information.\n");

    public static final AttributeSyntax FILTER_SET_SYNTAX = new AttributeSyntaxParser(new AttributeParser.FilterSetParser(), "" +
            "A filter-set name is made up of letters, digits, the\n" +
            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
            "must start with \"fltr-\", and the last character of a name\n" +
            "must be a letter or a digit.\n" +
            "\n" +
            "A filter-set name can also be hierarchical.  A hierarchical\n" +
            "set name is a sequence of set names and AS numbers separated\n" +
            "by colons \":\".  At least one component of such a name must\n" +
            "be an actual set name (i.e. start with \"fltr-\").  All the\n" +
            "set name components of a hierarchical filter-name have to be\n" +
            "filter-set names.\n");

    public static final AttributeSyntax IMPORT_SYNTAX = new AttributeSyntaxParser(new ImportParser(), "" +
            "[protocol <protocol-1>] [into <protocol-1>]\n" +
            "from <peering-1> [action <action-1>]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "from <peering-N> [action <action-N>]\n" +
            "accept <filter>\n");

    public static final AttributeSyntax IFADDR_SYNTAX = new AttributeSyntaxParser(new IfaddrParser(), "" +
            "<ipv4-address> masklen <integer> [action <action>]");

    public static final AttributeSyntax INTERFACE_SYNTAX = new AttributeSyntaxParser(new InterfaceParser(), "" +
            "afi <afi> <ipv4-address> masklen <integer> [action <action>]\n" +
            "afi <afi> <ipv6-address> masklen <integer> [action <action>]\n" +
            "          [tunnel <remote-endpoint-address>,<encapsulation>]\n");

    public static final AttributeSyntax IPV4_SYNTAX = new AttributeSyntaxParser(new AttributeParser.Ipv4ResourceParser(), "" +
            "<ipv4-address> - <ipv4-address>");

    public static final AttributeSyntax IPV6_SYNTAX = new AttributeSyntaxParser(new AttributeParser.Ipv6ResourceParser(), "" +
            "<ipv6-address>/<prefix>");
    public static final AttributeSyntax MNT_ROUTES_SYNTAX = new AttributeSyntaxParser(new AttributeParser.MntRoutesParser(), new Multiple(new HashMap<ObjectType, String>() {{
        put(ObjectType.AUT_NUM, "<mnt-name> [ { list of (<ipv4-address>/<prefix> or <ipv6-address>/<prefix>) } | ANY ]\n");
        put(ObjectType.INET6NUM, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
        put(ObjectType.INETNUM, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
        put(ObjectType.ROUTE, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
        put(ObjectType.ROUTE6, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
    }}));

    public static final AttributeSyntax MP_DEFAULT_SYNTAX = new AttributeSyntaxParser(new MpDefaultParser(), "" +
            "to <peering> [action <action>] [networks <filter>]\n");

    public static final AttributeSyntax MP_EXPORT_SYNTAX = new AttributeSyntaxParser(new MpExportParser(), "" +
            "[protocol <protocol-1>] [into <protocol-1>]\n" +
            "afi <afi-list>\n" +
            "to <peering-1> [action <action-1>]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "to <peering-N> [action <action-N>]\n" +
            "announce <filter>\n");

    public static final AttributeSyntax EXPORT_VIA_SYNTAX = new AttributeSyntaxParser(new ExportViaParser(), "" +
            "[protocol <protocol-1>] [into <protocol-2>]   \n" +
            "afi <afi-list>\n" +
            "<peering-1>\n" +
            "to <peering-2> [action <action-1>; <action-2>; ... <action-N>;]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "<peering-3>\n" +
            "to <peering-M> [action <action-1>; <action-2>; ... <action-N>;]\n" +
            "announce <filter>\n");

    public static final AttributeSyntax MP_FILTER_SYNTAX = new AttributeSyntaxParser(new MpFilterParser(), "" +
            "Logical expression which when applied to a set of multiprotocol\n" +
            "routes returns a subset of these routes. Please refer to RPSLng\n" +
            "Internet Draft for more information.\n");

    public static final AttributeSyntax MP_IMPORT_SYNTAX = new AttributeSyntaxParser(new MpImportParser(), "" +
            "[protocol <protocol-1>] [into <protocol-1>]\n" +
            "afi <afi-list>\n" +
            "from <peering-1> [action <action-1>]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "from <peering-N> [action <action-N>]\n" +
            "accept (<filter>|<filter> except <importexpression>|\n" +
            "        <filter> refine <importexpression>)\n");

    public static final AttributeSyntax IMPORT_VIA_SYNTAX = new AttributeSyntaxParser(new ImportViaParser(), "" +
            "[protocol <protocol-1>] [into <protocol-2>]\n" +
            "afi <afi-list>\n" +
            "<peering-1>\n" +
            "from <peering-2> [action <action-1>; <action-2>; ... <action-N>;]\n" +
            "    .\n" +
            "    .\n" +
            "    .\n" +
            "<peering-3>\n" +
            "from <peering-M> [action <action-1>; <action-2>; ... <action-N>;]\n" +
            "accept (<filter>|<filter> except <importexpression>|\n" +
            "        <filter> refine <importexpression>)\n");

    public static final AttributeSyntax MP_PEER_SYNTAX = new AttributeSyntaxParser(new MpPeerParser(), new Multiple(new HashMap<ObjectType, String>() {{
        put(ObjectType.INET_RTR, "" +
                "<protocol> afi <afi> <ipv4- or ipv6- address> <options>\n" +
                "| <protocol> <inet-rtr-name> <options>\n" +
                "| <protocol> <rtr-set-name> <options>\n" +
                "| <protocol> <peering-set-name> <options>\n");

        put(ObjectType.PEERING_SET, "" +
                "afi <afi> <peering>\n");

    }}));

    public static final AttributeSyntax MP_PEERING_SYNTAX = new AttributeSyntaxParser(new MpPeeringParser(), "" +
            "afi <afi> <peering>\n");

    public static final AttributeSyntax NSERVER_SYNTAX = new AttributeSyntaxParser(new AttributeParser.NServerParser(), "" +
            "Nameserver name as specified in RFC 1034 with or without\n" +
            "trailing dot (\".\").  The total length should not exceed\n" +
            "254 characters (octets).\n" +
            "\n" +
            "The nameserver name may be optionally followed by IPv4 address\n" +
            "in decimal dotted quad form (e.g. 192.0.2.1) or IPv6 address\n" +
            "in lowercase canonical form (Section 2.2.1, RFC 4291).\n" +
            "\n" +
            "The nameserver name may be followed by an IP address only when\n" +
            "the name is inside of the domain being delegated.\n");


    public static final AttributeSyntax OBJECT_NAME_SYNTAX = new AttributeSyntaxParser(new AttributeParser.NameParser(), "" +
            "Made up of letters, digits, the character underscore \"_\",\n" +
            "and the character hyphen \"-\"; the first character of a name\n" +
            "must be a letter, and the last character of a name must be a\n" +
            "letter or a digit.  The following words are reserved by\n" +
            "RPSL, and they can not be used as names:\n" +
            "\n" +
            " any as-any rs-any peeras and or not atomic from to at\n" +
            " action accept announce except refine networks into inbound\n" +
            " outbound\n" +
            "\n" +
            "Names starting with certain prefixes are reserved for\n" +             // TODO: [ES] implement per type
            "certain object types.  Names starting with \"as-\" are\n" +
            "reserved for as set names.  Names starting with \"rs-\" are\n" +
            "reserved for route set names.  Names starting with \"rtrs-\"\n" +
            "are reserved for router set names. Names starting with\n" +
            "\"fltr-\" are reserved for filter set names. Names starting\n" +
            "with \"prng-\" are reserved for peering set names. Names\n" +
            "starting with \"irt-\" are reserved for irt names.\n");

    public static final AttributeSyntax REFERRAL_SYNTAX = new AttributeSyntaxParser(new AttributeParser.NameParser());



    public static final AttributeSyntax PEER_SYNTAX = new AttributeSyntaxParser(new PeerParser(), "" +
            "<protocol> <ipv4-address> <options>\n" +
            "| <protocol> <inet-rtr-name> <options>\n" +
            "| <protocol> <rtr-set-name> <options>\n" +
            "| <protocol> <peering-set-name> <options>\n");

    public static final AttributeSyntax PEERING_SYNTAX = new AttributeSyntaxParser(new PeeringParser(), "" +
            "<peering>\n");

    public static final AttributeSyntax PINGABLE_SYNTAX = new AttributeSyntaxParser(new AttributeParser.IPAddressParser());

    public static final AttributeSyntax ROUTE_SET_SYNTAX = new AttributeSyntaxParser(new AttributeParser.RouteSetParser(), "" +
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
            "route-set names.\n");

    public static final AttributeSyntax RTR_SET_SYNTAX = new AttributeSyntaxParser(new AttributeParser.RtrSetParser(), "" +
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
            "to be router-set names.\n");

    public static final AttributeSyntax PEERING_SET_SYNTAX = new AttributeSyntaxParser(new AttributeParser.PeeringSetParser(), "" +
            "A peering-set name is made up of letters, digits, the\n" +
            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
            "must start with \"prng-\", and the last character of a name\n" +
            "must be a letter or a digit.\n" +
            "\n" +
            "A peering-set name can also be hierarchical.  A hierarchical\n" +
            "set name is a sequence of set names and AS numbers separated\n" +
            "by colons \":\".  At least one component of such a name must\n" +
            "be an actual set name (i.e. start with \"prng-\").  All the\n" +
            "set name components of a hierarchical peering-set name have\n" +
            "to be peering-set names.\n");

    public static final AttributeSyntax ROUTE_SYNTAX = new AttributeSyntaxParser(new AttributeParser.RouteResourceParser(), "" +
            "An address prefix is represented as an IPv4 address followed\n" +
            "by the character slash \"/\" followed by an integer in the\n" +
            "range from 0 to 32.  The following are valid address\n" +
            "prefixes: 128.9.128.5/32, 128.9.0.0/16, 0.0.0.0/0; and the\n" +
            "following address prefixes are invalid: 0/0, 128.9/16 since\n" +
            "0 or 128.9 are not strings containing four integers.\n");

    public static final AttributeSyntax ROUTE6_SYNTAX = new AttributeSyntaxParser(new AttributeParser.Route6ResourceParser(), "" +
            "<ipv6-address>/<prefix>\n");

    private final AttributeParser attributeParser;
    private final Documented description;

    public AttributeSyntaxParser(final AttributeParser attributeParser) {
        this(attributeParser, "");
    }

    public AttributeSyntaxParser(final AttributeParser attributeParser, final String description) {
        this(attributeParser, new Documented.Single(description));
    }

    public AttributeSyntaxParser(final AttributeParser attributeParser, final Documented description) {
        this.attributeParser = attributeParser;
        this.description = description;
    }

    @Override
    public boolean matches(final ObjectType objectType, final String value) {
        try {
            attributeParser.parse(value);
            return true;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return description.getDescription(objectType);
    }
}
