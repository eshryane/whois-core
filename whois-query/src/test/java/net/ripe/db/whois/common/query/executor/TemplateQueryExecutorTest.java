package net.ripe.db.whois.common.query.executor;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TemplateQueryExecutorTest {
    
    @Mock private QueryMessages queryMessages;
    private TemplateQueryExecutor subject;

    @Before
    public void setUp() throws Exception {
        subject = new TemplateQueryExecutor(queryMessages);

        when(queryMessages.invalidObjectType(any(CharSequence.class))).thenReturn(new Message(Messages.Type.ERROR, ""));
    }

    @Test
    public void supports_template() {
        assertThat(subject.supports(new Query("-t inetnum", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_case_insensitive() {
        assertThat(subject.supports(new Query("-t iNeTnUm", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_multiple() {
        assertThat(subject.supports(new Query("-t inetnum,inet6num", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_with_type() {
        assertThat(subject.supports(new Query("-t inetnum,inet6num -T inetnum 0/0", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_with_type_invalid() {
        assertThat(subject.supports(new Query("-t inetnum,inet6num -T inetnum", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_with_searchValue() {
        assertThat(subject.supports(new Query("-t inetnum,inet6num query", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_verbose() {
        assertThat(subject.supports(new Query("-v inetnum", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_verbose_case_insensitive() {
        assertThat(subject.supports(new Query("-v InEtNuM", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_verbose_multiple() {
        assertThat(subject.supports(new Query("-v inetnum,inetn6num", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_verbose_with_type() {
        assertThat(subject.supports(new Query("-v inetnum,inet6num -T inetnum 0/0", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_verbose_with_searchValue() {
        assertThat(subject.supports(new Query("-v inetnum,inet6num query", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_template_with_other_arguments() {
        assertThat(subject.supports(new Query("-V ripews -t person", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void getResponse() {
        for (final ObjectType objectType : ObjectType.values()) {
            final String name = objectType.getName();

            final CaptureResponseHandler templateResponseHandler = new CaptureResponseHandler();
            subject.execute(new Query("-t " + name, Query.Origin.LEGACY, false, queryMessages), templateResponseHandler);
            final String templateText = templateResponseHandler.getResponseObjects().iterator().next().toString();
            assertThat(templateText, containsString(name));

            final CaptureResponseHandler verboseResponseHandler = new CaptureResponseHandler();
            subject.execute(new Query("-v " + name, Query.Origin.LEGACY, false, queryMessages), verboseResponseHandler);
            final String verboseText = verboseResponseHandler.getResponseObjects().iterator().next().toString();
            assertThat(verboseText, containsString(name));

            assertThat(verboseText, not(is(templateText)));
        }
    }

    @Test
    public void getResponse_multiple_template() {
        testInvalidObjectType("-t", "inetnum,inet6num");
    }

    @Test
    public void getResponse_unknown_template() {
        testInvalidObjectType("-t", "unknown");
    }

    @Test
    public void getResponse_multiple_verbose() {
        testInvalidObjectType("-v", "inetnum,inet6num");
    }

    @Test
    public void getResponse_unknown_verbose() {
        testInvalidObjectType("-v", "unknown");
    }

    private void testInvalidObjectType(final String option, final String objectType) {
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(new Query(option + " " + objectType, Query.Origin.LEGACY, false, queryMessages), responseHandler);

        final String templateText = responseHandler.getResponseObjects().iterator().next().toString();
        assertThat(templateText, is(queryMessages.invalidObjectType(objectType).toString()));
    }
}
