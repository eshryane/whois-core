package net.ripe.db.whois.common.query.handler;

import com.google.common.net.InetAddresses;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.common.query.acl.AccessControlListManager;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.ResponseHandler;
import net.ripe.db.whois.common.query.executor.QueryExecutor;
import net.ripe.db.whois.common.query.query.Query;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.net.InetAddress;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class QueryHandler_BlockedTest {
    @Mock WhoisLog whoisLog;
    @Mock AccessControlListManager accessControlListManager;
    @Mock SourceContext sourceContext;
    @Mock QueryExecutor queryExecutor;
    @Mock QueryMessages queryMessages;
    QueryHandler subject;

    int contextId = 1;
    InetAddress remoteAddress = InetAddresses.forString("193.0.0.10");
    @Mock ResponseHandler responseHandler;

    @Before
    public void setUp() throws Exception {
        subject = new QueryHandler(whoisLog, accessControlListManager, sourceContext, queryMessages, queryExecutor);
        when(queryExecutor.supports(any(Query.class))).thenReturn(true);
        when(queryExecutor.isAclSupported()).thenReturn(true);
    }

    @Test
    public void blocked_permanently() {
        when(accessControlListManager.isDenied(remoteAddress)).thenReturn(true);
        final Query query = new Query("10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedPermanently(remoteAddress));
    }

    @Test
    public void blocked_permanently_proxy() {
        when(accessControlListManager.isDenied(remoteAddress)).thenReturn(true);
        final Query query = new Query("-VclientId,11.0.0.0 10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedPermanently(remoteAddress));
    }

    @Test
    public void blocked_permanently_proxy_client() {
        InetAddress clientAddress = InetAddresses.forString("11.0.0.0");
        when(accessControlListManager.canQueryPersonalObjects(remoteAddress)).thenReturn(true);
        when(accessControlListManager.isAllowedToProxy(remoteAddress)).thenReturn(true);
        when(accessControlListManager.isDenied(clientAddress)).thenReturn(true);

        final Query query = new Query("-VclientId,11.0.0.0 10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedPermanently(clientAddress));
    }

    @Test
    public void blocked_temporary() {
        when(accessControlListManager.canQueryPersonalObjects(remoteAddress)).thenReturn(false);
        final Query query = new Query("10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedTemporarily(remoteAddress));
    }

    @Test
    public void blocked_temporary_proxy() {
        when(accessControlListManager.canQueryPersonalObjects(remoteAddress)).thenReturn(false);
        final Query query = new Query("-VclientId,11.0.0.0 10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedTemporarily(remoteAddress));
    }

    @Test
    public void blocked_temporary_proxy_client() {
        InetAddress clientAddress = InetAddresses.forString("11.0.0.0");
        when(accessControlListManager.canQueryPersonalObjects(remoteAddress)).thenReturn(true);
        when(accessControlListManager.isAllowedToProxy(remoteAddress)).thenReturn(true);
        when(accessControlListManager.canQueryPersonalObjects(clientAddress)).thenReturn(false);

        final Query query = new Query("-VclientId,11.0.0.0 10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.BLOCKED, queryMessages.accessDeniedTemporarily(clientAddress));
    }

    @Test
    public void proxy_not_allowed() {
        when(accessControlListManager.canQueryPersonalObjects(remoteAddress)).thenReturn(true);
        when(accessControlListManager.isAllowedToProxy(remoteAddress)).thenReturn(false);

        final Query query = new Query("-VclientId,11.0.0.0 10.0.0.0", Query.Origin.LEGACY, false, queryMessages);
        expectedFailure(query, QueryCompletionInfo.PROXY_NOT_ALLOWED, queryMessages.notAllowedToProxy());
    }

    private void expectedFailure(final Query query, final QueryCompletionInfo queryCompletionInfo, final Message... messages) {
        try {
            subject.streamResults(query, remoteAddress, contextId, responseHandler);
            fail("Expected failure");
        } catch (QueryException e) {
            assertThat(e.getCompletionInfo(), is(queryCompletionInfo));
            assertThat(e.getMessages(), contains(messages));

            verify(whoisLog).logQueryResult(anyString(), eq(0), eq(0), eq(queryCompletionInfo), anyLong(), eq(remoteAddress), eq(contextId), eq(query.toString()));
            verify(responseHandler, never()).handle(any(ResponseObject.class));
        }
    }
}
