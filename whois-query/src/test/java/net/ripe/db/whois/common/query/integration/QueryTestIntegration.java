package net.ripe.db.whois.common.query.integration;

import com.google.common.collect.Sets;
import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.query.QueryFlag;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.query.query.QueryComponent;
import net.ripe.db.whois.common.query.support.AbstractQueryIntegrationTest;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@Category(IntegrationTest.class)
public class QueryTestIntegration extends AbstractQueryIntegrationTest {

    @Autowired QueryComponent queryComponent;

    final Query parse(String input) {
        return parseWithNewline(input);
    }

    private Query parseWithNewline(String input) {
        // [EB]: userinput will always be newline terminated
        return queryComponent.parse(input + "\n");
    }

    @Test
    public void empty() {
        try {
            parse("");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.noSearchKeySpecified()));
        }
    }

    @Test
    public void query_with_searchValue() {
        final Query query = parse("foo");

        assertTrue(query.isFiltered());
        assertTrue(query.isGrouping());
        assertTrue(query.isProxyValid());
        assertTrue(query.isReturningReferencedObjects());
        assertThat(query.getSearchValue(), is("foo"));
    }

    @Test
    public void query_with_space() {
        final Query query = parse("foo ");
        assertThat(query.getSearchValue(), is("foo"));
    }

    @Test
    public void query_ignores_C() {
        final Query query = parse("-C test");
        assertThat(query.hasOptions(), is(true));
        assertThat(query.getSearchValue(), is("test"));
    }

    @Test
    public void deprecated_R() {
        try {
            parse("-R test");
        } catch (QueryException e) {
            assertThat(e.getMessages(), hasSize(1));
            assertThat(e.getMessages().iterator().next(), is(queryMessages.malformedQuery()));
        }
    }

    @Test
    public void non_filtered() {
        final Query query = parse("-B foo");

        assertFalse(query.isFiltered());
    }

    @Test
    public void non_grouping() {
        final Query query = parse("-G foo");

        assertFalse(query.isGrouping());
    }

    @Test
    public void non_recursive() {
        final Query query = parse("-r foo");

        assertFalse(query.isReturningReferencedObjects());
    }

    @Test
    public void is_short_hand() {
        final Query query = parse("-F foo");

        assertTrue(query.isShortHand());
    }

    @Test
    public void short_hand_is_non_recursive() {
        final Query query = parse("-F foo");

        assertTrue(query.isShortHand());
        assertFalse(query.isReturningReferencedObjects());
    }

    @Test
    public void has_ip_flags() {
        final Set<QueryFlag> flags = Sets.newHashSet(QueryFlag.REVERSE_DOMAIN);
        for (final Query.MatchOperation matchOperation : Query.MatchOperation.values()) {
            if (matchOperation.getQueryFlag() != null) {
                flags.add(matchOperation.getQueryFlag());
            }
        }

        for (final QueryFlag queryFlag : flags) {
            for (final String flag : queryFlag.getFlags()) {
                final Query query = parse((flag.length() == 1 ? "-" : "--") + flag + " 10.0.0.0");
                assertThat("flag: " + flag, query.hasIpFlags(), is(true));
            }
        }
    }

    @Test
    public void match_operations_default_inetnum() {
        final Query query = parse("-T inetnum 10.0.0.0");

        assertNull(query.matchOperation());
    }

    @Test
    public void match_operations_default_inet6num() {
        final Query query = parse("-T inet6num ::0/0");

        assertNull(query.matchOperation());
    }

    @Test
    public void match_operations_no_default_for_maintainer() {
        final Query query = parse("-T mntner foo");

        assertNull(query.matchOperation());
    }

    @Test
    public void match_operations_empty() {
        final Query query = parse("foo");

        assertNull(query.matchOperation());
    }

    @Test
    public void recognize_flags_with_arguments() {
        String[] flagsWithArguments = {"t", "v", "q", "V"};

        final StringBuilder queryBuilder = new StringBuilder();
        for (String flag : flagsWithArguments) {
            queryBuilder.append("-").append(flag).append(" ").append(flag).append("-flag").append(" ");
        }
        queryBuilder.append("is wrong");

        final Query query = parse(queryBuilder.toString());
        assertThat(query.getSearchValue(), is("is wrong"));
    }

    @Test
    public void no_sources() {
        final Query query = parse("test");

        assertThat(query.getSources(), hasSize(0));
    }

    @Test
    public void source() {
        final Query query = parse("-s RIPE foo");

        assertThat(query.getSources(), contains("RIPE"));
    }

    @Test
    public void sources() {
        final Query query = parse("-s RIPE,TEST foo");

        assertThat(query.getSources(), contains("RIPE", "TEST"));
    }

    @Test
    public void missing_arguments_for_flags() {
        String[] flagsWithArguments = {"i", "s", "t", "v", "q", "V"};

        for (String flag : flagsWithArguments) {
            try {
                parse("-" + flag);
                fail("Missing argument for " + flag + " should throw an exception");
            } catch (QueryException e) {
                // OK
            }
        }
    }

    @Test
    public void single_type_invalid_searchkey() {
        try {
            parse("-T aut-num foo");
            fail("Expected query exception");
        } catch (QueryException e) {
            assertThat(e.getCompletionInfo(), Matchers.is(QueryCompletionInfo.PARAMETER_ERROR));
            assertThat(e.getMessages(), contains(queryMessages.invalidSearchKey()));
        }
    }

    @Test
    public void single_type() {
        final Query query = parse("-T aut-num AS1");
        assertTrue(query.hasObjectTypeFilter(ObjectType.AUT_NUM));
        assertThat(query.getSuppliedObjectTypes(), contains(ObjectType.AUT_NUM));
    }

    @Test
    public void empty_types() {
        final Query query = parse("TEST-DBM-MNT");
        assertThat(query.getSuppliedObjectTypes(), hasSize(0));
        assertThat(query.getObjectTypes(), not(hasSize(0)));
    }

    @Test
    public void multiple_types_casing() {
        final Query query = parse("-T aut-num,iNet6nUM,iNETnUm foo");
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertTrue(query.hasObjectTypeFilter(ObjectType.INET6NUM));
        assertFalse(query.hasObjectTypeFilter(ObjectType.AUT_NUM));
        assertThat(query.getSuppliedObjectTypes(), containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM, ObjectType.INET6NUM));
    }

    @Test
    public void multiple_types_with_empty_element() {
        Query query = parse("-T aut-num,,iNETnUm foo");
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertFalse(query.hasObjectTypeFilter(ObjectType.AUT_NUM));
        assertThat(query.getSuppliedObjectTypes(), containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM));

        query = parse("-T aut-num,,iNETnUm as112");
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertTrue(query.hasObjectTypeFilter(ObjectType.AUT_NUM));
        assertThat(query.getSuppliedObjectTypes(), containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM));
    }

    @Test
    public void short_types_casing() {
        final Query query = parse("-T in,rT,An foo");
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertFalse(query.hasObjectTypeFilter(ObjectType.ROUTE));
        assertFalse(query.hasObjectTypeFilter(ObjectType.AUT_NUM));
        assertThat(query.getSuppliedObjectTypes(), containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM, ObjectType.ROUTE));
    }

    @Test
    public void non_existing_types() {
        try {
            parse("-T aUT-Num,IAmInvalid,iNETnUm");
            fail("Non existing type should throw an exception");
        } catch (QueryException e) {
            assertThat(e.getMessage(), containsString("ERROR:103"));
        }
    }

    @Test
    public void type_option_without_space() {
        final Query query = parse("-Tinetnum dont_care");

        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertThat(query.getSuppliedObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void type_option_with_extra_space() {
        final Query query = parse("-T  inetnum dont_care");

        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertThat(query.getSuppliedObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void type_with_clustered_options() {
        final Query query = parse("-rT inetnum dont_care");

        assertFalse(query.isReturningReferencedObjects());
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertThat(query.getSuppliedObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void type_with_clustered_options_and_no_space() {
        final Query query = parse("-rTinetnum dont_care");

        assertFalse(query.isReturningReferencedObjects());
        assertTrue(query.hasObjectTypeFilter(ObjectType.INETNUM));
        assertThat(query.getSuppliedObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void proxied_for() {
        final Query query = parse("-VclientId,10.0.0.0 foo");

        assertEquals("clientId,10.0.0.0", query.getProxy());
    }

    @Test(expected = QueryException.class)
    public void proxied_for_invalid() {
        queryComponent.parse("-VclientId,ipAddress");
    }

    @Test
    public void one_element_proxy_has_no_proxy_ip() {
        final Query query = parse("-Vone foo");

        assertTrue(query.isProxyValid());
        assertFalse(query.hasProxyWithIp());
        assertThat(query.getProxyIp(), nullValue());
    }

    @Test
    public void proxy_with_ip() {
        final Query query = parse("-Vone,10.0.0.1 foo");

        assertTrue(query.isProxyValid());
        assertTrue(query.hasProxyWithIp());
    }

    @Test(expected = QueryException.class)
    public void proxy_with_invalid_ip() {
        parse("-Vone,two");
    }

    @Test(expected = QueryException.class)
    public void proxy_with_more_than_two_elements() {
        queryComponent.parse("-Vone,two,10.1.1.1");
    }

    @Test
    public void to_string_returns_input() {
        final Query query = parse("-r -GBTinetnum dont_care");

        assertEquals("-r -GBTinetnum dont_care", query.toString());
    }

    @Test
    public void only_keep_alive_flag_specified() {
        final Query query = parse("-k\r");
        assertTrue(query.hasKeepAlive());
        assertThat(query.getSearchValue(), is(""));
    }

    @Test
    public void only_keep_alive_flag_specified_longoption() {
        final Query query = parse("--persistent-connection\r");
        assertTrue(query.hasKeepAlive());
        assertThat(query.getSearchValue(), is(""));
    }

    @Test
    public void keep_alive_recognised() {
        final Query query = parse("-rBG -T inetnum --persistent-connection 192.168.200.0 - 192.168.200.255\r");
        assertTrue(query.hasKeepAlive());
        assertThat(query.getSearchValue(), is("192.168.200.0 - 192.168.200.255"));
    }

    @Test(expected = QueryException.class)
    public void invalidProxyShouldThrowException() {
        queryComponent.parse("-Vone,two,three -Tperson DW-RIPE");
    }

    @Test
    public void testNoInverse() {
        final Query query = queryComponent.parse("foo");

        assertThat(query.isInverse(), is(false));
    }

    @Test
    public void testInverseSingleAttribute() {
        final Query query = queryComponent.parse("-i mnt-by aardvark-mnt");

        assertThat(query.isInverse(), is(true));
        assertThat(query.getAttributeTypes(), containsInAnyOrder(AttributeType.MNT_BY));
        assertThat(query.getSearchValue(), is("aardvark-mnt"));
        assertNull(query.matchOperation());
    }

    @Test
    public void testInverseSingleAttributeWithTypeFilter() {
        final Query query = queryComponent.parse("-i mnt-by aardvark-mnt -T inetnum");

        assertThat(query.isInverse(), is(true));
        assertThat(query.getAttributeTypes(), containsInAnyOrder(AttributeType.MNT_BY));
        assertThat(query.getSearchValue(), is("aardvark-mnt"));
        assertNull(query.matchOperation());
    }

    @Test
    public void testInverseSingleAttributeShort() {
        final Query query = queryComponent.parse("-i mb aardvark-mnt");

        assertThat(query.isInverse(), is(true));
        assertThat(query.getAttributeTypes(), containsInAnyOrder(AttributeType.MNT_BY));
        assertThat(query.getSearchValue(), is("aardvark-mnt"));
    }

    @Test
    public void testInverseInvalidAttribute() {
        try {
            queryComponent.parse("-i some-invalid aardvark-mnt");
            fail("Expected query exception");
        } catch (QueryException e) {
            assertThat(e.getMessage(), is(queryMessages.invalidAttributeType("some-invalid").toString()));
        }
    }

    @Test
    public void testInverseMultipleAttributes() {
        final Query query = queryComponent.parse("-i mb,mz aardvark-mnt");

        assertThat(query.isInverse(), is(true));
        assertThat(query.getAttributeTypes(), containsInAnyOrder(AttributeType.MNT_REF, AttributeType.MNT_BY));
        assertThat(query.getSearchValue(), is("aardvark-mnt"));
    }

    @Test
    public void testMultipleObjectTypes() {
        final Query query = queryComponent.parse("-T inet6num,domain,inetnum searchkey");

        assertThat(query.getSearchValue(), is("searchkey"));
        assertThat(query.getObjectTypes(), contains(ObjectType.INETNUM, ObjectType.INET6NUM, ObjectType.DOMAIN));
    }

    @Test
    public void testMultipleSeparatedObjectTypes() {
        final Query query = queryComponent.parse("-T inetnum -T inet6num,domain searchkey");

        assertThat(query.getObjectTypes(), contains(ObjectType.INETNUM, ObjectType.INET6NUM, ObjectType.DOMAIN));
    }

    @Test
    public void testMultipleSeparatedAttributeTypes() {
        final Query query = queryComponent.parse("-i mnt-by -i mnt-ref,mnt-lower foo");

        assertThat(query.getAttributeTypes(), containsInAnyOrder(AttributeType.MNT_BY, AttributeType.MNT_REF, AttributeType.MNT_LOWER));
    }

    @Test
    public void illegal_range_ipv4_more_all() {
        illegalRange("-M 0/0");
    }

    @Test
    public void illegal_range_ipv4_more() {
        illegalRange("-m 0/0");
    }

    @Test
    public void illegal_range_ipv6_more_all() {
        illegalRange("-M ::0/0");
    }

    @Test
    public void illegal_range_ipv6_more() {
        illegalRange("-m ::0/0");
    }

    private void illegalRange(final String queryString) {
        try {
            queryComponent.parse(queryString);
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessage(), is(queryMessages.illegalRange().toString()));
        }
    }

    @Test(expected = QueryException.class)
    public void multiple_proxies() {
        parse("-V ripews,188.111.4.162   -V 85.25.132.61");
    }

    @Test
    public void attributes_person() {
        final Query query = queryComponent.parse("-i person name");

        assertThat(query.getAttributeTypes(), contains(AttributeType.ADMIN_C, AttributeType.TECH_C, AttributeType.ZONE_C, AttributeType.AUTHOR, AttributeType.PING_HDL));
    }

    @Test
    public void attributes_person_and_others() {
        final Query query = queryComponent.parse("-i mb,person,ml name");

        assertThat(query.getAttributeTypes(), contains(AttributeType.MNT_BY, AttributeType.ADMIN_C, AttributeType.TECH_C, AttributeType.ZONE_C, AttributeType.AUTHOR, AttributeType.PING_HDL, AttributeType.MNT_LOWER));
    }

    @Test
    public void getAsBlockRange() {
        Query query = queryComponent.parse("-r -T as-block AS1-AS2");
        assertTrue(query.getAsBlockRangeOrNull().getBegin() == 1);
        assertTrue(query.getAsBlockRangeOrNull().getEnd() == 2);
    }

    @Test
    public void not_lookupBothDirections() {
        Query query = queryComponent.parse("10.0.0.0");
        assertFalse(query.isLookupInBothDirections());
    }

    @Test
    public void getIpKeyOrNull_both_directions_forward() {
        Query query = queryComponent.parse("-d 10.0.0.0");
        assertTrue(query.isLookupInBothDirections());
        assertThat(query.getIpKeyOrNull().toString(), is("10.0.0.0/32"));
    }

    @Test
    public void getIpKeyOrNull_both_directions_reverse_domain() {
        Query query = queryComponent.parse("-d 10.in-addr.arpa");
        assertTrue(query.isLookupInBothDirections());
        assertThat(query.getIpKeyOrNull().toString(), is("10.0.0.0/8"));
    }

    @Test
    public void not_isReturningIrt() {
        Query query = queryComponent.parse("10.0.0.0");
        assertFalse(query.isReturningIrt());
    }

    @Test
    public void isReturningIrt() {
        Query query = queryComponent.parse("-c 10.0.0.0");
        assertTrue(query.isReturningIrt());
    }

    @Test
    public void hasSources() {
        Query query = queryComponent.parse("-s RIPE,TEST 10.0.0.0");
        assertTrue(query.hasSources());
        assertThat(query.getSources(), contains("RIPE", "TEST"));
    }

    @Test
    public void not_hasSources() {
        Query query = queryComponent.parse("10.0.0.0");
        assertFalse(query.hasSources());
    }

    @Test
    public void isPrimaryObjectsOnly() {
        Query query = queryComponent.parse("-rG 10.0.0.0");
        assertTrue(query.isPrimaryObjectsOnly());
    }

    @Test
    public void isPrimaryObjectsOnly_grouping() {
        Query query = queryComponent.parse("-r 10.0.0.0");
        assertFalse(query.isPrimaryObjectsOnly());
    }

    @Test
    public void isPrimaryObjectsOnly_relatedTo() {
        Query query = queryComponent.parse("-G 10.0.0.0");
        assertFalse(query.isPrimaryObjectsOnly());
    }

    @Test
    public void isPrimaryObjectsOnly_irt() {
        Query query = queryComponent.parse("-rGc 10.0.0.0");
        assertFalse(query.isPrimaryObjectsOnly());
    }

    @Test(expected = QueryException.class)
    public void system_info_invalid_option() {
        Query query = queryComponent.parse("-q invalid");
        query.getSystemInfoOption();
    }

    @Test(expected = QueryException.class)
    public void system_info_with_multiple_arguments() {
        Query query = queryComponent.parse("-q version -q invalid");
        query.getSystemInfoOption();
    }

    @Test(expected = QueryException.class)
    public void system_info_multiple_flags_no_arguments() {
        Query query = queryComponent.parse("-q -q");
        query.getSystemInfoOption();
    }

    @Test
    public void system_info_version_flag() {
        Query query = queryComponent.parse("-q version");
        assertThat(query.isSystemInfo(), is(true));
        assertThat(query.getSystemInfoOption(), is(Query.SystemInfoOption.VERSION));
    }

    @Test
    public void system_info_types_flag() {
        Query query = queryComponent.parse("-q types");
        assertThat(query.isSystemInfo(), is(true));
        assertThat(query.getSystemInfoOption(), is(Query.SystemInfoOption.TYPES));
    }

    @Test
    public void system_info_types_flag_longoption() {
        Query query = queryComponent.parse("--types");
        assertThat(query.isSystemInfo(), is(true));
        assertThat(query.getSystemInfoOption(), is(Query.SystemInfoOption.TYPES));
    }

    @Test
    public void isAllSources() {
        Query query = queryComponent.parse("-a foo");
        assertThat(query.isAllSources(), is(true));
    }

    @Test
    public void not_isAllSources() {
        Query query = queryComponent.parse("foo");
        assertThat(query.isAllSources(), is(false));
    }

    @Test
    public void isBrief() {
        Query query = queryComponent.parse("-b 10.0.0.0");
        assertThat(query.isBriefAbuseContact(), is(true));
    }

    @Test
    public void isBrief_forces_grouping_and_irt() {
        Query query = queryComponent.parse("-b -C 10.0.0.0");
        assertThat(query.isBriefAbuseContact(), is(true));
        assertThat(query.isGrouping(), is(false));
        assertThat(query.isReturningIrt(), is(true));
    }

    @Test
    public void not_isBrief() {
        Query query = queryComponent.parse("foo");
        assertThat(query.isBriefAbuseContact(), is(false));
    }

    @Test
    public void isKeysOnly() {
        Query query = queryComponent.parse("-K 10.0.0.0");
        assertThat(query.isKeysOnly(), is(true));
    }

    @Test
    public void isKeysOnly_forces_non_grouping() {
        Query query = queryComponent.parse("-K 10.0.0.0");
        assertThat(query.isKeysOnly(), is(true));
        assertThat(query.isGrouping(), is(false));
    }

    @Test
    public void not_isKeysOnly() {
        Query query = queryComponent.parse("foo");
        assertThat(query.isKeysOnly(), is(false));
    }

    @Test
    public void not_related_when_isKeysOnly() {
        Query query = queryComponent.parse("-K 10.0.0.0");
        assertThat(query.isReturningReferencedObjects(), is(false));
    }

    @Test
    public void not_irt_when_isKeysOnline() {
        Query query = queryComponent.parse("-c -K 10.0.0.0");
        assertThat(query.isReturningIrt(), is(false));
    }

    @Test
    public void hasOption() {
        Query query = queryComponent.parse("-s RIPE -T inetnum 10.0.0.0");
        assertThat(query.hasOption(QueryFlag.SOURCES), is(true));
        assertThat(query.hasOption(QueryFlag.SELECT_TYPES), is(true));
        assertThat(query.hasOption(QueryFlag.NO_REFERENCED), is(false));
    }

    @Test
    public void validTemplateQuery() {
        Query query = queryComponent.parse("-t person");
        assertThat(query.hasOption(QueryFlag.TEMPLATE), is(true));
        assertThat(query.isTemplate(), is(true));
        assertThat(query.getTemplateOption(), is("person"));
    }

    @Test(expected = QueryException.class)
    public void templateQueryMultipleArguments() {
        Query query = queryComponent.parse("-t person -t role");
        query.getTemplateOption();
    }

    @Test
    public void validVerboseTemplateQuery() {
        Query query = queryComponent.parse("-v person");
        assertThat(query.hasOption(QueryFlag.VERBOSE), is(true));
        assertThat(query.isVerbose(), is(true));
        assertThat(query.getVerboseOption(), is("person"));
    }

    @Test(expected = QueryException.class)
    public void verboseTemplateQueryMultipleArguments() {
        Query query = queryComponent.parse("-v person -v role");
        query.getVerboseOption();
    }

    @Test
    public void systemInfoWithExtraFlagAndArgument() {
        Query query = queryComponent.parse("-q version -t person");
        assertThat(query.getSystemInfoOption(), is(Query.SystemInfoOption.VERSION));
        assertThat(query.getTemplateOption(), is("person"));
    }

    @Test
    public void multiple_match_operations() {
        try {
            queryComponent.parse("-m -x 10.0.0.0");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.duplicateIpFlagsPassed()));
        }
    }

    @Test
    public void match_operations_without_ipkey() {
        Query query = queryComponent.parse("-m test");
        assertThat(query.getWarnings(), hasItem(queryMessages.uselessIpFlagPassed()));
    }

    @Test
    public void brief_without_ipkey() {
        try {
            queryComponent.parse("-b test");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.malformedQuery()));
        }
    }

    @Test
    public void brief_not_showing_referenced_objects() {
        final Query query = queryComponent.parse("-b 10.0.0.0");
        assertThat(query.isReturningReferencedObjects(), is(false));
    }

    @Test
    public void brief_not_grouping() {
        final Query query = queryComponent.parse("-b 10.0.0.0");
        assertThat(query.isGrouping(), is(false));
    }

    @Test
    public void unsupportedQuery() {
        try {
            queryComponent.parse("...");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.invalidSearchKey()));
        }
    }

    @Test
    public void nonVersionQuery() {
        Query query = queryComponent.parse("10.0.0.0");
        assertThat(query.hasOption(QueryFlag.LIST_VERSIONS), is(false));
        assertThat(query.isVersionList(), is(false));
        assertThat(query.hasOption(QueryFlag.SHOW_VERSION), is(false));
        assertThat(query.isObjectVersion(), is(false));
    }

    @Test
    public void versionlistQuery() {
        Query query = queryComponent.parse("--list-versions 10.0.0.0");
        assertThat(query.hasOption(QueryFlag.LIST_VERSIONS), is(true));
        assertThat(query.isVersionList(), is(true));
    }

    @Test
    public void versionQuery() {
        Query query = queryComponent.parse("--show-version 1 10.0.0.0");
        assertThat(query.hasOption(QueryFlag.SHOW_VERSION), is(true));
        assertThat(query.isObjectVersion(), is(true));
    }

    @Test
    public void allow_only_k_T_and_V_options_for_version_queries() {
        final String[] validQueries = {
                "--show-version 1 AS12 -k",
                "--show-version 1 AS12 -V fred",
                "--show-version 1 AS12 -k -V fred",
                "--list-versions AS12 -k -V fred",
                "--list-versions AS12 -V fred",
                "--list-versions AS12 -k",
                "--diff-versions 1:2 AS12",
                "--diff-versions 1:2 AS12 -k",
                "--diff-versions 1:2 AS12 -V fred",
                "--show-version 1 AS12 -T aut-num",
        };

        for (String query : validQueries) {
            queryComponent.parse(query);
        }

        final String[] invalidQueries = {
                "--show-version 1 AS12 -B",
                "--list-versions AS12 -G",
                "--list-versions AS12 -V fred --no-tag-info",
                "--list-versions AS12 -k --show-version 1 AS12",
                "--diff-versions 1:2 AS12 -k --show-version 1",
                "--diff-versions 1:2 AS12 -B",
                "--diff-versions 1:2 AS12 -V fred --no-tag-info"
        };

        for (String query : invalidQueries) {
            try {
                queryComponent.parse(query);
                fail(String.format("%s should not succeed", query));
            } catch (final QueryException e) {
                assertThat(e.getMessage(), containsString("cannot be used together"));
            }
        }
    }

    @Test
    public void versionDiffQuery() {
        Query query = queryComponent.parse("--diff-versions 1:2 10.0.0.0");
        assertThat(query.hasOption(QueryFlag.DIFF_VERSIONS), is(true));
        assertThat(query.isVersionDiff(), is(true));
    }

    @Test
    public void filter_tag_include_no_query() {
        try {
            queryComponent.parse("--filter-tag-include unref");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.noSearchKeySpecified()));
        }
    }

    @Test
    public void filter_tag_exclude_no_query() {
        try {
            queryComponent.parse("--filter-tag-exclude unref");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.noSearchKeySpecified()));
        }
    }

    @Test
    public void filter_tag_include_unref() {
        final Query query = queryComponent.parse("--filter-tag-include unref test");
        assertThat(query.hasOption(QueryFlag.FILTER_TAG_INCLUDE), is(true));
    }

    @Test
    public void filter_tag_exclude_unref() {
        final Query query = queryComponent.parse("--filter-tag-exclude unref test");
        assertThat(query.hasOption(QueryFlag.FILTER_TAG_EXCLUDE), is(true));
    }


    @Test
    public void filter_tag_include_unref_different_casing() {
        final Query query = queryComponent.parse("--filter-tag-include UnReF test");
        assertThat(query.hasOption(QueryFlag.FILTER_TAG_INCLUDE), is(true));
    }

    @Test
    public void filter_tag_exclude_unref_different_casing() {
        final Query query = queryComponent.parse("--filter-tag-exclude UnReF test");
        assertThat(query.hasOption(QueryFlag.FILTER_TAG_EXCLUDE), is(true));
    }


    @Test
    public void show_tag_info() {
        final Query query = queryComponent.parse("--show-tag-info TEST-MNT");
        assertThat(query.hasOption(QueryFlag.SHOW_TAG_INFO), is(true));
    }

    @Test
    public void no_tag_info() {
        final Query query = queryComponent.parse("--no-tag-info TEST-MNT");
        assertThat(query.hasOption(QueryFlag.NO_TAG_INFO), is(true));
    }

    @Test
    public void no_tag_info_and_show_tag_info_in_the_same_query() {
        try {
            queryComponent.parse("--no-tag-info --show-tag-info TEST-MNT");
            fail();
        } catch (QueryException e) {
            assertThat(e.getMessage(), containsString("The flags \"--show-tag-info\" and \"--no-tag-info\" cannot be used together."));
        }
    }

    @Test
    public void grs_search_types_specified_none() {
        final Query query = queryComponent.parse("--resource 10.0.0.0");
        assertThat(query.getObjectTypes(), contains(
                ObjectType.INETNUM,
                ObjectType.ROUTE,
                ObjectType.DOMAIN));
    }

    @Test
    public void grs_search_types_specified_single() {
        final Query query = queryComponent.parse("--resource -Tinetnum 10.0.0.0");
        assertThat(query.getObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void inverse_query_should_not_filter_object_types() {
        final Query query = queryComponent.parse("-i nic-hdl 10.0.0.1");
        assertThat(query.getObjectTypes(), hasSize(21));
    }

    @Test
    public void grs_search_types_specified_non_resource() {
        final Query query = queryComponent.parse("--resource -Tinetnum,mntner 10.0.0.0");
        assertThat(query.getObjectTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void grs_enables_all_sources() {
        final Query query = queryComponent.parse("--resource 10.0.0.0");
        assertThat(query.isAllSources(), is(false));
        assertThat(query.isResource(), is(true));
    }    
    
    @Test
    public void invalid_combination() {
        try {
            queryComponent.parse("-b -F 10.0.0.0");
            fail("Expected exception");
        } catch (QueryException e) {
            assertThat(e.getMessages(), contains(queryMessages.invalidCombinationOfFlags("-b, --abuse-contact", "-F, --brief")));
        }
    }

}
