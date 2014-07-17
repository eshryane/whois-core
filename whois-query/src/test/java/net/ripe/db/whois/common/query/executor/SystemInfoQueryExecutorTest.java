package net.ripe.db.whois.common.query.executor;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.source.SourceContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Iterator;

import static net.ripe.db.whois.common.domain.CIString.ciSet;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SystemInfoQueryExecutorTest {

    private SystemInfoQueryExecutor subject;

    @Mock private SourceContext sourceContext;
    @Mock private QueryMessages queryMessages;

    @Before
    public void setUp() throws Exception {
        subject = new SystemInfoQueryExecutor(sourceContext, queryMessages);

        when(queryMessages.malformedQuery(any(String.class))).thenReturn(new Message(Messages.Type.ERROR, "malformed query"));
    }

    @Test
    public void supports_version_ignore_case() {
        assertThat(subject.supports(new Query("-q Version", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_types_ignore_case() {
        assertThat(subject.supports(new Query("-q Types", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_sources_ignore_case() {
        assertThat(subject.supports(new Query("-q Sources", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void types_query() {
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(new Query("-q types", Query.Origin.LEGACY, false, queryMessages), responseHandler);
        Iterator<? extends ResponseObject> iterator = responseHandler.getResponseObjects().iterator();
        String responseString = iterator.next().toString();

        assertThat(iterator.hasNext(), is(false));

        for (ObjectType objectType : ObjectType.values()) {
            assertThat(responseString, containsString(objectType.getName()));
        }
    }

    @Test
    public void types_query_invalid_argument() {
        try {
            subject.execute(new Query("-q invalid", Query.Origin.LEGACY, false, queryMessages), new CaptureResponseHandler());
            fail("expected QueryException to be thrown");
        } catch (QueryException qe) {
            assertThat(qe.getMessage(), containsString("malformed query"));
        }
    }

    @Test
    public void version_query() {
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(new Query("-q version", Query.Origin.LEGACY, false, queryMessages), responseHandler);
        Iterator<? extends ResponseObject> iterator = responseHandler.getResponseObjects().iterator();
        String responseString = iterator.next().toString();

        assertThat(iterator.hasNext(), is(false));
        assertThat(responseString, containsString("% whois-server"));
    }

    @Test
    public void sources_query() {
        when(sourceContext.getAllSourceNames()).thenReturn(ciSet("RIPE"));

        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(new Query("-q sources", Query.Origin.LEGACY, false, queryMessages), responseHandler);
        Iterator<? extends ResponseObject> iterator = responseHandler.getResponseObjects().iterator();
        String responseString = iterator.next().toString();

        assertThat(iterator.hasNext(), is(false));
        assertThat(responseString, containsString("RIPE:3:N:0-0\n"));
    }
}
