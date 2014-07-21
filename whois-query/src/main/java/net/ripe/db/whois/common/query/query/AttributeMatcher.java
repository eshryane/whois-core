package net.ripe.db.whois.common.query.query;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.ip.IpInterval;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;

import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

abstract class AttributeMatcher { // TODO [AK] Figure out what can be delegated to AttributeSyntax
    static final AttributeMatcher ANYTHING_CONTAINING_ALPHA_MATCHER = new RegExpMatcher(".*[A-Z].*");
    static final AttributeMatcher AS_NUMBER_MATCHER = new RegExpMatcher("^AS\\d+$");
    static final AttributeMatcher AS_SET_MATCHER = new RegExpMatcher("(^|.*:)AS-[A-Z0-9_-]*(:.*|$)");
    static final AttributeMatcher DOMAIN_MATCHER = new RegExpMatcher("^[A-Z0-9/-]*(\\.[A-Z0-9-]+)*\\.?$");
    static final AttributeMatcher EMAIL_MATCHER = new RegExpMatcher("^.+@.+$");
    static final AttributeMatcher FILTER_SET_MATCHER = new RegExpMatcher("(^|.*:)FLTR-[A-Z0-9_-]*[A-Z0-9](:.*|$)");
    static final AttributeMatcher IRT_MATCHER = new RegExpMatcher("^IRT-[A-Z0-9_-]+[A-Z0-9]$");
    static final AttributeMatcher KEY_CERT_MATCHER = new RegExpMatcher("^(PGPKEY-|X509).+");
    static final AttributeMatcher NETNAME_MATCHER = new RegExpMatcher("^[A-Z0-9_-]+");
    static final AttributeMatcher NIC_HANDLE_MATCHER = new RegExpMatcher("^[A-Z0-9-]+$");
    static final AttributeMatcher ORGANISATION_MATCHER = new RegExpMatcher("^ORG-([A-Z]{2,4}([1-9][0-9]{0,5})?(-[A-Z]([A-Z0-9_-]{0,7}[A-Z0-9])))$");
    static final AttributeMatcher PEERING_SET_MATCHER = new RegExpMatcher("(^|.*:)PRNG-[A-Z0-9_-]*[A-Z0-9](:.*|$)");
    static final AttributeMatcher POEM_MATCHER = new RegExpMatcher("^POEM-[A-Z0-9][A-Z0-9_-]*$");
    static final AttributeMatcher POETIC_FORM_MATCHER = new RegExpMatcher("^FORM-[A-Z0-9][A-Z0-9_-]*$");
    static final AttributeMatcher ROUTE_SET_MATCHER = new RegExpMatcher("(^|.*:)RS-[A-Z0-9_-]*[A-Z0-9](:.*|$)");
    static final AttributeMatcher RTR_SET_MATCHER = new RegExpMatcher("(^|.*:)RTRS-[A-Z0-9_-]*[A-Z0-9](:.*|$)");

    static final AttributeMatcher AS_BLOCK_MATCHER = new AttributeMatcher() {
        @Override
        public boolean matches(final Query query) {
            return query.getAsBlockRangeOrNull() != null;
        }
    };

    static final AttributeMatcher IPV4_MATCHER = new AttributeMatcher() {
        @Override
        public boolean matches(final Query query) {
            final IpInterval<?> ipKeyOrNull = query.getIpKeyOrNull();
            return query.getRouteOrigin() == null && ipKeyOrNull != null && ipKeyOrNull.getAttributeType().equals(AttributeTypes.INETNUM);
        }
    };

    static final AttributeMatcher IPV6_MATCHER = new AttributeMatcher() {
        @Override
        public boolean matches(final Query query) {
            final IpInterval<?> ipKeyOrNull = query.getIpKeyOrNull();
            return query.getRouteOrigin() == null && ipKeyOrNull != null && ipKeyOrNull.getAttributeType().equals(AttributeTypes.INET6NUM);
        }
    };

    static final AttributeMatcher ROUTE4_MATCHER = new AttributeMatcher() {
        @Override
        public boolean matches(final Query query) {
            return query.getRouteOrigin() != null && query.getIpKeyOrNull().getAttributeType().equals(AttributeTypes.INETNUM);
        }
    };

    static final AttributeMatcher ROUTE6_MATCHER = new AttributeMatcher() {
        @Override
        public boolean matches(final Query query) {
            return query.getRouteOrigin() != null && query.getIpKeyOrNull().getAttributeType().equals(AttributeTypes.INET6NUM);
        }
    };

    static final class RegExpMatcher extends AttributeMatcher {
        private final Pattern pattern;

        public RegExpMatcher(final String pattern) {
            this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        }

        @Override
        public boolean matches(final Query query) {
            return pattern.matcher(query.getSearchValue()).matches();
        }
    }

    static Map<AttributeType, Collection<AttributeMatcher>> attributeMatchers = Maps.newHashMap();

    static {
        attributeMatchers.put(AttributeTypes.AS_BLOCK, Sets.newHashSet(AttributeMatcher.AS_BLOCK_MATCHER));
        attributeMatchers.put(AttributeTypes.AS_SET, Sets.newHashSet(AttributeMatcher.AS_SET_MATCHER));
        attributeMatchers.put(AttributeTypes.AUT_NUM, Sets.newHashSet(AttributeMatcher.AS_NUMBER_MATCHER));
        attributeMatchers.put(AttributeTypes.DOMAIN, Sets.newHashSet(AttributeMatcher.DOMAIN_MATCHER, AttributeMatcher.IPV4_MATCHER, AttributeMatcher.IPV6_MATCHER));
        attributeMatchers.put(AttributeTypes.E_MAIL, Sets.newHashSet(AttributeMatcher.EMAIL_MATCHER));
        attributeMatchers.put(AttributeTypes.FILTER_SET, Sets.newHashSet(AttributeMatcher.FILTER_SET_MATCHER));
        attributeMatchers.put(AttributeTypes.INET6NUM, Sets.newHashSet(AttributeMatcher.IPV6_MATCHER, AttributeMatcher.NETNAME_MATCHER));
        attributeMatchers.put(AttributeTypes.INETNUM, Sets.newHashSet(AttributeMatcher.IPV4_MATCHER, AttributeMatcher.NETNAME_MATCHER));
        attributeMatchers.put(AttributeTypes.INET_RTR, Sets.newHashSet(AttributeMatcher.DOMAIN_MATCHER));
        attributeMatchers.put(AttributeTypes.IRT, Sets.newHashSet(AttributeMatcher.IRT_MATCHER));
        attributeMatchers.put(AttributeTypes.KEY_CERT, Sets.newHashSet(AttributeMatcher.KEY_CERT_MATCHER));
        attributeMatchers.put(AttributeTypes.MNTNER, Sets.newHashSet(AttributeMatcher.ANYTHING_CONTAINING_ALPHA_MATCHER));
        attributeMatchers.put(AttributeTypes.NETNAME, Sets.newHashSet(AttributeMatcher.NETNAME_MATCHER));
        attributeMatchers.put(AttributeTypes.NIC_HDL, Sets.newHashSet(AttributeMatcher.NIC_HANDLE_MATCHER));
        attributeMatchers.put(AttributeTypes.ORG_NAME, Sets.newHashSet(AttributeMatcher.ANYTHING_CONTAINING_ALPHA_MATCHER));
        attributeMatchers.put(AttributeTypes.ORGANISATION, Sets.newHashSet(AttributeMatcher.ORGANISATION_MATCHER));
        attributeMatchers.put(AttributeTypes.PEERING_SET, Sets.newHashSet(AttributeMatcher.PEERING_SET_MATCHER));
        attributeMatchers.put(AttributeTypes.PERSON, Sets.newHashSet(AttributeMatcher.ANYTHING_CONTAINING_ALPHA_MATCHER));
        attributeMatchers.put(AttributeTypes.POEM, Sets.newHashSet(AttributeMatcher.POEM_MATCHER));
        attributeMatchers.put(AttributeTypes.POETIC_FORM, Sets.newHashSet(AttributeMatcher.POETIC_FORM_MATCHER));
        attributeMatchers.put(AttributeTypes.ROLE, Sets.newHashSet(AttributeMatcher.ANYTHING_CONTAINING_ALPHA_MATCHER));
        attributeMatchers.put(AttributeTypes.ROUTE, Sets.newHashSet(AttributeMatcher.IPV4_MATCHER, AttributeMatcher.ROUTE4_MATCHER));
        attributeMatchers.put(AttributeTypes.ROUTE6, Sets.newHashSet(AttributeMatcher.IPV6_MATCHER, AttributeMatcher.ROUTE6_MATCHER));
        attributeMatchers.put(AttributeTypes.ROUTE_SET, Sets.newHashSet(AttributeMatcher.ROUTE_SET_MATCHER));
        attributeMatchers.put(AttributeTypes.RTR_SET, Sets.newHashSet(AttributeMatcher.RTR_SET_MATCHER));
    }

    static boolean fetchableBy(final AttributeType attributeType, final Query query) {
        for (final AttributeMatcher matcher : attributeMatchers.get(attributeType)) {
            try {
                if (matcher.matches(query)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {}
        }

        return false;
    }

    abstract boolean matches(Query query);
}
