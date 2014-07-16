package net.ripe.db.whois.common.query.support;

import net.ripe.db.whois.common.support.AbstractDaoTest;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.QueryServer;
import net.ripe.db.whois.common.query.acl.IpResourceConfiguration;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration(locations = {"classpath:applicationContext-query-test.xml"})
public abstract class AbstractQueryIntegrationTest extends AbstractDaoTest {
    public static final String HOST = "localhost";

    @Autowired protected QueryServer queryServer;
    @Autowired protected IpResourceConfiguration ipResourceConfiguration;
    @Autowired protected QueryMessages queryMessages;

    // TODO: [AH] not do this for each test, but reinit context only where needed
    @Before
    public final void setUpAbstractIntegrationTest() throws Exception {
        databaseHelper.clearAclLimits();
        databaseHelper.insertAclIpLimit("0/0", -1, true);
        databaseHelper.insertAclIpLimit("::0/0", -1, true);
        ipResourceConfiguration.reload();
    }

    public String stripHeader(final String response) {
        String result = response;

        result = stripHeader(result, queryMessages.termsAndConditions().toString());

        return result;
    }

    private static String stripHeader(final String response, final String headerString) {
        if (response.startsWith(StringUtils.trim(headerString))) {
            if (response.length() < headerString.length()) {
                return "";
            } else {
                return response.substring(headerString.length() + 1);
            }
        }

        return response;
    }
}
