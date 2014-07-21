package net.ripe.db.whois.common.rpsl.attributetype.impl;

import com.google.common.collect.Sets;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;

import java.util.Collection;
import java.util.HashMap;

import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.AnySyntax.*;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.AttributeSyntaxParser.*;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.AttributeSyntaxRegexp.*;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.ComponentsSyntax.COMPONENTS_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.ExportCompsSyntax.EXPORT_COMPS_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.GeolocSyntax.GEOLOC_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.InjectSyntax.INJECT_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.MemberOfSyntax.MEMBER_OF_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.MembersSyntax.MEMBERS_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.MembersSyntax.MP_MEMBERS_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.OrgTypeSyntax.ORG_TYPE_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.PersonRoleSyntax.PERSON_ROLE_NAME_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.RoutePrefixSyntax.HOLES_SYNTAX;
import static net.ripe.db.whois.common.rpsl.attributesyntax.impl.StatusSyntax.STATUS_SYNTAX;

/**
 * Created by michel on 7/18/14.
 */
public final class AttributeTypes {

    public static final AttributeType AUTH = new AttributeTypeImpl(
            "auth",
            "at",
            "Defines an authentication scheme to be used.",
            AUTH_SCHEME_SYNTAX,
            Sets.newHashSet(ObjectType.KEY_CERT));

    public static final AttributeType ABUSE_MAILBOX = new AttributeTypeImpl("abuse-mailbox", "am",
            "Specifies the e-mail address to which abuse complaints should be sent. " +
                    "This attribute should only be used in the ROLE object. It will be deprecated from any other object. " +
                    "Adding this attribute to a ROLE object, then referencing it in an \"abuse-c:\" attribute of an ORGANISATION object, " +
                    "will remove any query limits for the ROLE object. These ROLE objects are considered to include only commercial data.",
            EMAIL_SYNTAX
    );

    public static final AttributeType ABUSE_C = new AttributeTypeImpl("abuse-c", "au",
            "References an abuse contact. " +
                    "This can only be a ROLE object containing an \"abuse-mailbox:\" attribute. " +
                    "Making this reference will remove any query limits for the ROLE object. " +
                    "These ROLE objects are considered to include only commercial data.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.ROLE)
    );

    public static final AttributeType ADDRESS = new AttributeTypeImpl("address", "ad",
            "Full postal address of a contact",
            FREE_FORM_SYNTAX);

    public static final AttributeType ADMIN_C = new AttributeTypeImpl("admin-c", "ac",
            "References an on-site administrative contact.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.PERSON, ObjectType.ROLE));

    public static final AttributeType AGGR_BNDRY = new AttributeTypeImpl("aggr-bndry", "ab",
            "Defines a set of ASes, which form the aggregation boundary.",
            AGGR_BNDRY_SYNTAX);

    public static final AttributeType AGGR_MTD = new AttributeTypeImpl("aggr-mtd", "ag",
            "Specifies how the aggregate is generated.",
            AGGR_MTD_SYNTAX);

    public static final AttributeType ALIAS = new AttributeTypeImpl("alias", "az",
            "The canonical DNS name for the router.",
            ALIAS_SYNTAX);

    public static final AttributeType ASSIGNMENT_SIZE = new AttributeTypeImpl("assignment-size", "ae",
            "Specifies the size of blocks assigned to end users from this aggregated inet6num assignment.",
            NUMBER_SYNTAX);

    public static final AttributeType AS_BLOCK = new AttributeTypeImpl("as-block", "ak",
            "Range of AS numbers.",
            AS_BLOCK_SYNTAX);

    public static final AttributeType AS_NAME = new AttributeTypeImpl("as-name", "aa",
            "A descriptive name associated with an AS.",
            OBJECT_NAME_SYNTAX);

    public static final AttributeType AS_SET = new AttributeTypeImpl("as-set", "as",
            "Defines the name of the set.",
            AS_SET_SYNTAX);

    public static final AttributeType AUTHOR = new AttributeTypeImpl("author", "ah",
            "References a poem author.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.PERSON, ObjectType.ROLE));

    public static final AttributeType AUT_NUM = new AttributeTypeImpl("aut-num", "an",
            "The autonomous system number.",
            AS_NUMBER_SYNTAX);

    public static final AttributeType CERTIF = new AttributeTypeImpl("certif", "ce",
            "Contains the public key.",
            CERTIF_SYNTAX);

    public static final AttributeType CHANGED = new AttributeTypeImpl("changed", "ch",
            "Specifies who submitted the update, and when the object was updated. " +
                    "This attribute is filtered from the default whois output.",
            CHANGED_SYNTAX
    );

    public static final AttributeType COMPONENTS = new AttributeTypeImpl("components", "co",
            "The \"components:\" attribute defines what component routes are used to form the aggregate.",
            COMPONENTS_SYNTAX);

    public static final AttributeType COUNTRY = new AttributeTypeImpl("country", "cy",
            "Identifies the country.",
            COUNTRY_CODE_SYNTAX);

    public static final AttributeType DEFAULT = new AttributeTypeImpl("default", "df",
            "Specifies default routing policies.",
            DEFAULT_SYNTAX);

    public static final AttributeType DESCR = new AttributeTypeImpl("descr", "de",
            "A short decription related to the object.",
            FREE_FORM_SYNTAX);

    public static final AttributeType DOMAIN = new AttributeTypeImpl("domain", "dn",
            "Domain name.",
            DOMAIN_SYNTAX);

    public static final AttributeType DS_RDATA = new AttributeTypeImpl("ds-rdata", "ds",
            "DS records for this domain.",
            DS_RDATA_SYNTAX);

    public static final AttributeType ENCRYPTION = new AttributeTypeImpl("encryption", "en",
            "References a key-cert object representing a CSIRT public key used " +
                    "to encrypt correspondence sent to the CSIRT.",
            KEY_CERT_SYNTAX
            , Sets.newHashSet(ObjectType.KEY_CERT)
    );

    public static final AttributeType EXPORT = new AttributeTypeImpl("export", "ex",
            "Specifies an export policy expression.",
            EXPORT_SYNTAX);

    public static final AttributeType EXPORT_COMPS = new AttributeTypeImpl("export-comps", "ec",
            "Defines the set's policy filter, a logical expression which when applied to a set of " +
                    "routes returns a subset of these routes.",
            EXPORT_COMPS_SYNTAX
    );

    public static final AttributeType E_MAIL = new AttributeTypeImpl("e-mail", "em",
            "The e-mail address of a person, role, organisation or irt team. " +
                    "This attribute is filtered from the default whois output when at least one of the objects " +
                    "returned by the query contains an abuse-mailbox attribute.",
            EMAIL_SYNTAX
    );

    public static final AttributeType FAX_NO = new AttributeTypeImpl("fax-no", "fx",
            "The fax number of a contact.",
            PHONE_SYNTAX);

    public static final AttributeType FILTER = new AttributeTypeImpl("filter", "fi",
            "Defines the set's policy filter.",
            FILTER_SYNTAX);

    public static final AttributeType FILTER_SET = new AttributeTypeImpl("filter-set", "fs",
            "Defines the name of the filter.",
            FILTER_SET_SYNTAX);

    public static final AttributeType FINGERPR = new AttributeTypeImpl("fingerpr", "fp",
            "A fingerprint of a key certificate generated by the database.",
            GENERATED_SYNTAX);

    public static final AttributeType FORM = new AttributeTypeImpl("form", "fr",
            "Specifies the identifier of a registered poem type.",
            POETIC_FORM_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.POETIC_FORM));

    public static final AttributeType GEOLOC = new AttributeTypeImpl("geoloc", "gl",
            "The location coordinates for the resource.",
            GEOLOC_SYNTAX);

    public static final AttributeType HOLES = new AttributeTypeImpl("holes", "ho",
            "Lists the component address prefixes that are not reachable through the aggregate route" +
                    "(perhaps that part of the address space is unallocated).",
            HOLES_SYNTAX, AttributeValueType.LIST_VALUE
    );

    public static final AttributeType IFADDR = new AttributeTypeImpl("ifaddr", "if",
            "Specifies an interface address within an Internet router.",
            IFADDR_SYNTAX);

    public static final AttributeType IMPORT = new AttributeTypeImpl("import", "ip",
            "Specifies import policy expression.",
            IMPORT_SYNTAX);

    public static final AttributeType INET6NUM = new AttributeTypeImpl("inet6num", "i6",
            "Specifies a range of IPv6 addresses in prefix notation.",
            IPV6_SYNTAX);

    public static final AttributeType INETNUM = new AttributeTypeImpl("inetnum", "in",
            "Specifies a range of IPv4 that inetnum object presents. " +
                    "The ending address should be greater than the starting one.",
            IPV4_SYNTAX
    );

    public static final AttributeType INET_RTR = new AttributeTypeImpl("inet-rtr", "ir",
            "Fully qualified DNS name of the inet-rtr without trailing \".\".",
            INET_RTR_SYNTAX);

    public static final AttributeType INJECT = new AttributeTypeImpl("inject", "ij",
            "Specifies which routers perform the aggregation and when they perform it.",
            INJECT_SYNTAX);

    public static final AttributeType INTERFACE = new AttributeTypeImpl("interface", "ie",
            "Specifies a multiprotocol interface address within an Internet router.",
            INTERFACE_SYNTAX);

    public static final AttributeType IRT = new AttributeTypeImpl("irt", "it",
            "Specifies the name of the irt object. The name should start with the prefix \"IRT-\", " +
                    "reserved for this type of object.",
            IRT_SYNTAX
    );

    public static final AttributeType IRT_NFY = new AttributeTypeImpl("irt-nfy", "iy",
            "Specifies the e-mail address to be notified when a reference to the irt object is added or removed.",
            EMAIL_SYNTAX);

    public static final AttributeType KEY_CERT = new AttributeTypeImpl("key-cert", "kc",
            "Defines the public key stored in the database.",
            KEY_CERT_SYNTAX);

    public static final AttributeType LANGUAGE = new AttributeTypeImpl("language", "ln",
            "Identifies the language.",
            LANGUAGE_CODE_SYNTAX);

    public static final AttributeType LOCAL_AS = new AttributeTypeImpl("local-as", "la",
            "Specifies the autonomous system that operates the router.",
            AS_NUMBER_SYNTAX);

    public static final AttributeType MBRS_BY_REF = new AttributeTypeImpl("mbrs-by-ref", "mr",
            "This attribute can be used in all \"set\" objects; it allows indirect population of a set. " +
                    "If this attribute is used, the set also includes objects of the corresponding type " +
                    "(aut-num objects for as-set, for example) that are protected by one of these maintainers " +
                    "and whose \"member-of:\" attributes refer to the name of the set. " +
                    "If the value of a \"mbrs-by-ref:\" attribute is ANY, any object of the corresponding type " +
                    "referring to the set is a member of the set. If the \"mbrs-by-ref:\" attribute is missing, " +
                    "the set is defined explicitly by the \"members:\" attribute.",
            MBRS_BY_REF_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MEMBERS = new AttributeTypeImpl("members", "ms",
            "Lists the members of the set.",
            MEMBERS_SYNTAX, AttributeValueType.LIST_VALUE); // No reference checking should be performed for members!

    public static final AttributeType MEMBER_OF = new AttributeTypeImpl("member-of", "mo",
            "This attribute can be used in the route, aut-num and inet-rtr classes. " +
                    "The value of the \"member-of:\" attribute identifies a set object that this object wants " +
                    "to be a member of. This claim, however, should be acknowledged by a " +
                    "respective \"mbrs-by-ref:\" attribute in the referenced object.",
            MEMBER_OF_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.AS_SET, ObjectType.ROUTE_SET, ObjectType.RTR_SET)
    );

    public static final AttributeType METHOD = new AttributeTypeImpl("method", "mh",
            "Defines the type of the public key.",
            METHOD_SYNTAX);

    public static final AttributeType MNTNER = new AttributeTypeImpl("mntner", "mt",
            "A unique identifier of the mntner object.",
            OBJECT_NAME_SYNTAX);

    public static final AttributeType MNT_BY = new AttributeTypeImpl("mnt-by", "mb",
            "Specifies the identifier of a registered mntner object used for authorisation of operations " +
                    "performed with the object that contains this attribute.",
            OBJECT_NAME_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MNT_DOMAINS = new AttributeTypeImpl("mnt-domains", "md",
            "Specifies the identifier of a registered mntner object used for reverse domain authorisation. " +
                    "Protects domain objects. The authentication method of this maintainer object will be used for " +
                    "any encompassing reverse domain object.",
            OBJECT_NAME_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MNT_IRT = new AttributeTypeImpl("mnt-irt", "mi",
            "May appear in an inetnum or inet6num object. It points to an irt object representing a " +
                    "Computer Security Incident Response Team (CSIRT) that handles security incidents for " +
                    "the address space specified by the inetnum or inet6num object.",
            IRT_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.IRT)
    );

    public static final AttributeType MNT_LOWER = new AttributeTypeImpl("mnt-lower", "ml",
            "Specifies the identifier of a registered mntner object used for hierarchical authorisation. " +
                    "Protects creation of objects directly (one level) below in the hierarchy of an object type. " +
                    "The authentication method of this maintainer object will then be used upon creation of any " +
                    "object directly below the object that contains the \"mnt-lower:\" attribute.",
            OBJECT_NAME_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MNT_NFY = new AttributeTypeImpl("mnt-nfy", "mn",
            "Specifies the e-mail address to be notified when an object protected by a mntner is successfully updated.",
            EMAIL_SYNTAX);

    public static final AttributeType MNT_REF = new AttributeTypeImpl("mnt-ref", "mz",
            "Specifies the maintainer objects that are entitled to add references " +
                    "to the organisation object from other objects.",
            OBJECT_NAME_SYNTAX, AttributeValueType.LIST_VALUE,
            Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MNT_ROUTES = new AttributeTypeImpl("mnt-routes", "mu",
            new Documented.Multiple(new HashMap<ObjectType, String>() {{
                put(ObjectType.AUT_NUM, "" +
                        "This attribute references a maintainer object which is used in\n" +
                        "determining authorisation for the creation of route6 objects.\n" +
                        "This entry is for the mnt-routes attribute of aut-num class.\n" +
                        "After the reference to the maintainer, an optional list of\n" +
                        "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                        "follow. The default, when no additional set items are\n" +
                        "specified, is \"ANY\" or all more specifics.");

                put(ObjectType.INET6NUM, "" +
                        "This attribute references a maintainer object which is used in\n" +
                        "determining authorisation for the creation of route6 objects.\n" +
                        "This entry is for the mnt-routes attribute of route6 and inet6num classes.\n" +
                        "After the reference to the maintainer, an optional list of\n" +
                        "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                        "follow. The default, when no additional set items are\n" +
                        "specified, is \"ANY\" or all more specifics.");

                put(ObjectType.INETNUM, "" +
                        "This attribute references a maintainer object which is used in\n" +
                        "determining authorisation for the creation of route objects.\n" +
                        "After the reference to the maintainer, an optional list of\n" +
                        "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                        "follow. The default, when no additional set items are\n" +
                        "specified, is \"ANY\" or all more specifics. Please refer to\n" +
                        "RFC-2622 for more information.");

                put(ObjectType.ROUTE, "" +
                        "This attribute references a maintainer object which is used in\n" +
                        "determining authorisation for the creation of route objects.\n" +
                        "After the reference to the maintainer, an optional list of\n" +
                        "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                        "follow. The default, when no additional set items are\n" +
                        "specified, is \"ANY\" or all more specifics. Please refer to\n" +
                        "RFC-2622 for more information.");

                put(ObjectType.ROUTE6, "" +
                        "This attribute references a maintainer object which is used in\n" +
                        "determining authorisation for the creation of route6 objects.\n" +
                        "This entry is for the mnt-routes attribute of route6 and inet6num classes.\n" +
                        "After the reference to the maintainer, an optional list of\n" +
                        "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                        "follow. The default, when no additional set items are\n" +
                        "specified, is \"ANY\" or all more specifics.");

            }}),
            MNT_ROUTES_SYNTAX, Sets.newHashSet(ObjectType.MNTNER)
    );

    public static final AttributeType MP_DEFAULT = new AttributeTypeImpl("mp-default", "ma",
            "Specifies default multiprotocol routing policies.",
            MP_DEFAULT_SYNTAX);

    public static final AttributeType MP_EXPORT = new AttributeTypeImpl("mp-export", "me",
            "Specifies a multiprotocol export policy expression.",
            MP_EXPORT_SYNTAX);

    public static final AttributeType EXPORT_VIA = new AttributeTypeImpl("export-via", "ev",
            "Specifies an export policy expression targeted at a non-adjacent network.",
            EXPORT_VIA_SYNTAX);

    public static final AttributeType MP_FILTER = new AttributeTypeImpl("mp-filter", "mf",
            "Defines the set's multiprotocol policy filter.",
            MP_FILTER_SYNTAX);

    public static final AttributeType MP_IMPORT = new AttributeTypeImpl("mp-import", "my",
            "Specifies multiprotocol import policy expression.",
            MP_IMPORT_SYNTAX);

    public static final AttributeType IMPORT_VIA = new AttributeTypeImpl("import-via", "iv",
            "Specifies an import policy expression targeted at a non-adjacent network.",
            IMPORT_VIA_SYNTAX);

    public static final AttributeType MP_MEMBERS = new AttributeTypeImpl("mp-members", "mm",
            "Lists the multiprotocol members of the set.",
            MP_MEMBERS_SYNTAX, AttributeValueType.LIST_VALUE);

    public static final AttributeType MP_PEER = new AttributeTypeImpl("mp-peer", "mp",
            new Documented.Multiple(new HashMap<ObjectType, String>() {{
                put(ObjectType.INET_RTR, "Details of any (interior or exterior) multiprotocol router peerings.");
                put(ObjectType.PEERING_SET, "Defines a multiprotocol peering that can be used for importing or exporting routes.");
            }}),
            MP_PEER_SYNTAX
    );

    public static final AttributeType MP_PEERING = new AttributeTypeImpl("mp-peering", "mg",
            "Defines a multiprotocol peering that can be used for importing or exporting routes.",
            MP_PEERING_SYNTAX);

    public static final AttributeType NETNAME = new AttributeTypeImpl("netname", "na",
            "The name of a range of IP address space.",
            NETNAME_SYNTAX);

    public static final AttributeType NIC_HDL = new AttributeTypeImpl("nic-hdl", "nh",
            "Specifies the NIC handle of a role or person object. When creating an object, one can also " +
                    "specify an \"AUTO\" NIC handle by setting the value of the attribute to \"AUTO-1\" " +
                    "or AUTO-1<Initials>. In such case the database will assign the NIC handle automatically.",
            NIC_HANDLE_SYNTAX
    );

    public static final AttributeType NOTIFY = new AttributeTypeImpl("notify", "ny",
            "Specifies the e-mail address to which notifications of changes to an object should be sent. " +
                    "This attribute is filtered from the default whois output.",
            EMAIL_SYNTAX
    );

    public static final AttributeType NSERVER = new AttributeTypeImpl("nserver", "ns",
            "Specifies the nameservers of the domain.",
            NSERVER_SYNTAX);

    public static final AttributeType ORG = new AttributeTypeImpl("org", "og",
            "Points to an existing organisation object representing the entity that holds the resource.",
            ORGANISATION_SYNTAX
            , Sets.newHashSet(ObjectType.ORGANISATION));

    public static final AttributeType ORG_NAME = new AttributeTypeImpl("org-name", "on",
            "Specifies the name of the organisation that this organisation object represents in the RIPE " +
                    "Database. This is an ASCII-only text attribute. The restriction is because this attribute is " +
                    "a look-up key and the whois protocol does not allow specifying character sets in queries. " +
                    "The user can put the name of the organisation in non-ASCII character sets in " +
                    "the \"descr:\" attribute if required.",
            ORG_NAME_SYNTAX
    );

    public static final AttributeType ORG_TYPE = new AttributeTypeImpl("org-type", "ot",
            "Specifies the type of the organisation.",
            ORG_TYPE_SYNTAX);

    public static final AttributeType ORGANISATION = new AttributeTypeImpl("organisation", "oa",
            "Specifies the ID of an organisation object. When creating an object, one has to specify " +
                    "an \"AUTO\" ID by setting the value of the attribute to \"AUTO-1\" or \"AUTO-1<letterCombination>\", " +
                    "so the database will assign the ID automatically.",
            ORGANISATION_SYNTAX
    );

    public static final AttributeType ORIGIN = new AttributeTypeImpl("origin", "or",
            "Specifies the AS that originates the route." +
                    "The corresponding aut-num object should be registered in the database.",
            AS_NUMBER_SYNTAX
            , Sets.newHashSet(ObjectType.AUT_NUM)
    );

    public static final AttributeType OWNER = new AttributeTypeImpl("owner", "ow",
            "Specifies the owner of the public key.",
            GENERATED_SYNTAX);

    public static final AttributeType PEER = new AttributeTypeImpl("peer", "pe",
            "Details of any (interior or exterior) router peerings.",
            PEER_SYNTAX);

    public static final AttributeType PEERING = new AttributeTypeImpl("peering", "pg",
            "Defines a peering that can be used for importing or exporting routes.",
            PEERING_SYNTAX);

    public static final AttributeType PEERING_SET = new AttributeTypeImpl("peering-set", "ps",
            "Specifies the name of the peering-set.",
            PEERING_SET_SYNTAX);

    public static final AttributeType PERSON = new AttributeTypeImpl("person", "pn",
            "Specifies the full name of an administrative, technical or zone contact person for " +
                    "other objects in the database.",
            PERSON_ROLE_NAME_SYNTAX
    );

    public static final AttributeType PHONE = new AttributeTypeImpl("phone", "ph",
            "Specifies a telephone number of the contact.",
            PHONE_SYNTAX);

    public static final AttributeType PING_HDL = new AttributeTypeImpl("ping-hdl", "pc",
            "References a person or role capable of responding to queries concerning the IP address(es) " +
                    "specified in the 'pingable' attribute.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.PERSON, ObjectType.ROLE)
    );

    public static final AttributeType PINGABLE = new AttributeTypeImpl("pingable", "pa",
            "Allows a network operator to advertise an IP address of a node that should be reachable from outside " +
                    "networks. This node can be used as a destination address for diagnostic tests. " +
                    "The IP address must be within the address range of the prefix containing this attribute.",
            PINGABLE_SYNTAX
    );

    public static final AttributeType POEM = new AttributeTypeImpl("poem", "po",
            "Specifies the title of the poem.",
            POEM_SYNTAX);

    public static final AttributeType POETIC_FORM = new AttributeTypeImpl("poetic-form", "pf",
            "Specifies the poem type.",
            POETIC_FORM_SYNTAX);

    public static final AttributeType REFERRAL_BY = new AttributeTypeImpl("referral-by", "rb",
            "Mandatory historical attribute referencing a mntner name. Not used. Suggest setting it to this mntner name.",
            REFERRAL_SYNTAX
            , Sets.newHashSet(ObjectType.MNTNER));

    public static final AttributeType REF_NFY = new AttributeTypeImpl("ref-nfy", "rn",
            "Specifies the e-mail address to be notified when a reference to the organisation object is added " +
                    "or removed. This attribute is filtered from the default whois output when at least one of the " +
                    "objects returned by the query contains an abuse-mailbox attribute.",
            EMAIL_SYNTAX
    );

    public static final AttributeType REMARKS = new AttributeTypeImpl("remarks", "rm",
            "Contains remarks.",
            FREE_FORM_SYNTAX);

    public static final AttributeType ROLE = new AttributeTypeImpl("role", "ro",
            "Specifies the full name of a role entity, e.g. RIPE DBM.",
            ORG_NAME_SYNTAX);

    public static final AttributeType ROUTE = new AttributeTypeImpl("route", "rt",
            "Specifies the prefix of the interAS route. Together with the \"origin:\" attribute, " +
                    "constitutes a primary key of the route object.",
            ROUTE_SYNTAX
    );

    public static final AttributeType ROUTE6 = new AttributeTypeImpl("route6", "r6",
            "Specifies the IPv6 prefix of the interAS route. Together with the \"origin:\" attribute," +
                    "constitutes a primary key of the route6 object.",
            ROUTE6_SYNTAX
    );

    public static final AttributeType ROUTE_SET = new AttributeTypeImpl("route-set", "rs",
            "Specifies the name of the route set. It is a primary key for the route-set object.",
            ROUTE_SET_SYNTAX);

    public static final AttributeType RTR_SET = new AttributeTypeImpl("rtr-set", "is",
            "Defines the name of the rtr-set.",
            RTR_SET_SYNTAX);

    public static final AttributeType SIGNATURE = new AttributeTypeImpl("signature", "sg",
            "References a key-cert object representing a CSIRT public key used by the team to sign their correspondence.",
            KEY_CERT_SYNTAX
            , Sets.newHashSet(ObjectType.KEY_CERT));

    public static final AttributeType SOURCE = new AttributeTypeImpl("source", "so",
            "Specifies the registry where the object is registered. Should be \"RIPE\" for the RIPE Database.",
            SOURCE_SYNTAX);

    public static final AttributeType STATUS = new AttributeTypeImpl("status", "st",
            "Specifies the status of the resource.",
            STATUS_SYNTAX);

    public static final AttributeType TECH_C = new AttributeTypeImpl("tech-c", "tc",
            "References a technical contact.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.PERSON, ObjectType.ROLE));

    public static final AttributeType TEXT = new AttributeTypeImpl("text", "tx",
            "Text of the poem. Must be humorous, but not malicious or insulting.",
            FREE_FORM_SYNTAX);

    public static final AttributeType UPD_TO = new AttributeTypeImpl("upd-to", "dt",
            "Specifies the e-mail address to be notified when an object protected by a mntner is unsuccessfully updated.",
            EMAIL_SYNTAX);

    public static final AttributeType ZONE_C = new AttributeTypeImpl("zone-c", "zc",
            "References a zone contact.",
            NIC_HANDLE_SYNTAX
            , Sets.newHashSet(ObjectType.PERSON, ObjectType.ROLE));

    public static Collection<AttributeType> values() {
        return AttributeTypeImpl.values();
    }

    public static AttributeType getByNameOrNull(String name) {
        return AttributeTypeImpl.getByNameOrNull(name);
    }
    public static AttributeType getByName(String name) {
        return AttributeTypeImpl.getByName(name);
    }
}
