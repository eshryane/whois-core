package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.apache.commons.lang.Validate;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class AttributeMatcherTest {

    @Mock private QueryMessages queryMessages;
    
    @Test
    public void searchKeyTypesName() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.PERSON, new Query("name", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.PERSON, new Query("one-two-three", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchKeyTypesOrganisationId() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ORGANISATION, new Query("ORG-AX1-RIPE", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ORGANISATION, new Query("oRg-aX1-rIPe", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.ORGANISATION, new Query("name", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchKeyTypesNicHandle() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.NIC_HDL, new Query("AA1-DEV", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.NIC_HDL, new Query("aA1-deV", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.NIC_HDL, new Query("name", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchKeyEmail() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.E_MAIL, new Query("cac37ak@ripe.net", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.E_MAIL, new Query("person@domain.com", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.E_MAIL, new Query("me@some.nl", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchInetnum() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ROUTE, new Query("10.11.12.0/24", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.INETNUM, new Query("10.11.12.0/24", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INET6NUM, new Query("10.11.12.0/24", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.ROUTE6, new Query("10.11.12.0/24", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchInet6num() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.INET6NUM, new Query("2001::/32", Query.Origin.LEGACY, false, queryMessages)));
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ROUTE6, new Query("2001::/32", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.ROUTE, new Query("2001::/32", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INETNUM, new Query("2001::/32", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchRoute() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ROUTE, new Query("10.11.12.0/24AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INETNUM, new Query("10.11.12.0/24AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INET6NUM, new Query("10.11.12.0/24AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.ROUTE6, new Query("10.11.12.0/24AS3333", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void searchRoute6() {
        assertTrue(AttributeMatcher.fetchableBy(AttributeType.ROUTE6, new Query("2001::/32AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.ROUTE, new Query("2001::/32AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INETNUM, new Query("2001::/32AS3333", Query.Origin.LEGACY, false, queryMessages)));
        assertFalse(AttributeMatcher.fetchableBy(AttributeType.INET6NUM, new Query("2001::/32AS3333", Query.Origin.LEGACY, false, queryMessages)));
    }

    @Test
    public void checkAllSupported() {
        for (final ObjectType objectType : ObjectType.values()) {
            final ObjectTemplate template = ObjectTemplate.getTemplate(objectType);
            for (final AttributeType lookupAttribute : template.getLookupAttributes()) {
                Validate.isTrue(AttributeMatcher.attributeMatchers.containsKey(lookupAttribute), "No matcher for lookup attribute: " + lookupAttribute + " defined for " + objectType);
            }
        }
    }
}
