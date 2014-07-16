package net.ripe.db.whois.common.query;


import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.support.AbstractDaoTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
public class QueryMessagesTestIntegration extends AbstractDaoTest {

    @Autowired QueryMessages subject;

    @Test
    public void equality() {
        Message message = subject.relatedTo("key");
        Message clone = subject.relatedTo("key");
        Message noClone = subject.relatedTo("key2");
        Message sameArgs = subject.invalidObjectType("key2");

        assertThat(message, is(message));
        assertThat(message, is(clone));
        assertFalse(message.equals(null));
        assertFalse(message.equals(1));
        assertFalse(message.equals(noClone));
        assertFalse(noClone.equals(sameArgs));

        assertThat(message.hashCode(), is(clone.hashCode()));
    }

    @Test
    public void headerShouldContainLinkToTermsAndConditions() {
        assertThat(subject.termsAndConditions().toString(), containsString("http://www.ripe.net/db/support/db-terms-conditions.pdf"));
    }

    @Test
    public void duplicateIpFlagsPassedShouldContainError() {
        assertThat(subject.duplicateIpFlagsPassed().toString(), containsString("%ERROR:901:"));
    }

    @Test
    public void restApiExpectsAbuseContactsInSpecificFormat() {
        assertThat(subject.abuseCShown("193.0.0.0 - 193.0.7.255", "abuse@ripe.net").toString(), is("% Abuse contact for '193.0.0.0 - 193.0.7.255' is 'abuse@ripe.net'\n"));
    }

    @Test
    public void internalErrorMessageShouldContainErrorCode() {
        assertThat(subject.internalErroroccurred().toString(), containsString("%ERROR:100:"));
    }

    @Test
    public void noSearchKeySpecifiedShouldContainError() {
        assertThat(subject.noSearchKeySpecified().toString(), containsString("%ERROR:106:"));
    }

    @Test
    public void noResultsMessageShouldContainErrorCode() {
        assertThat(subject.noResults("RIPE").toString(), containsString("%ERROR:101:"));
    }

    @Test
    public void accessDeniedPermanentlyShouldContainErrorCode() throws UnknownHostException {
        assertThat(subject.accessDeniedPermanently(InetAddress.getLocalHost()).toString(), containsString("%ERROR:201:"));
    }

    @Test
    public void accessDeniedTemporarilyMessageShouldContainErrorCode() throws UnknownHostException {
        assertThat(subject.accessDeniedTemporarily(InetAddress.getLocalHost()).toString(), containsString("%ERROR:201:"));
    }

    @Test
    public void tooLongInputStringShouldContainErrorCode() {
        assertThat(subject.inputTooLong().toString(), containsString("%ERROR:107:"));
    }

    @Test
    public void invalidObjectTypeShouldContainErrorCode() {
        assertThat(subject.invalidObjectType("").toString(), containsString("%ERROR:103:"));

    }

    @Test
    public void invalidInetnumMessageShouldContainErrorCode() {
        assertThat(subject.uselessIpFlagPassed().toString(), containsString("%WARNING:902:"));
    }

    @Test
    public void malformedQueryShouldContainError() {
        assertThat(subject.malformedQuery().toString(), containsString("%ERROR:111:"));
    }

    @Test
    public void notAllowedToProxyShouldContainError() {
        assertThat(subject.notAllowedToProxy().toString(), containsString("%ERROR:203:"));
    }
}
