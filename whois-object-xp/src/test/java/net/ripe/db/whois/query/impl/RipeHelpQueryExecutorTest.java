package net.ripe.db.whois.query.impl;

import net.ripe.db.whois.query.IQuery;
import net.ripe.db.whois.query.IQueryResponse;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * Created by yogesh on 7/17/14.
 */
public class RipeHelpQueryExecutorTest {

    private RipeHelpQueryExecutor subject = new RipeHelpQueryExecutor();

    @Test
    public void testMe() {
        IQueryResponse queryResponse = subject.execute(new IQuery() {
            @Override
            public void setArgValue(String key, String value) {
            }

            @Override
            public String getArgValue(String key) {
                return null;
            }
        });
        assertNotNull(queryResponse);
    }
}
