package net.ripe.db.whois.common.query.executor;

import com.google.common.base.Splitter;
import net.ripe.db.whois.common.query.QueryFlag;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.query.Query;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class HelpQueryExecutorTest {

    @Mock QueryMessages queryMessages;
    private HelpQueryExecutor subject;

    @Before
    public void setUp() throws Exception {
        subject = new HelpQueryExecutor();
    }

    @Test
    public void supports_help() {
        assertThat(subject.supports(new Query("help", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_help_ignore_case() {
        assertThat(subject.supports(new Query("HeLp", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void supports_help_with_other_argument() {
        assertThat(subject.supports(new Query("help invalid", Query.Origin.LEGACY, false, queryMessages)), is(false));
    }

    @Test
    public void supports_help_with_other_flags() {
        assertThat(subject.supports(new Query("help -T person", Query.Origin.LEGACY, false, queryMessages)), is(false));
    }

    @Test
    public void getResponse() {
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(null, responseHandler);
        final String helpText = responseHandler.getResponseObjects().get(0).toString();

        assertThat(helpText, containsString("NAME"));
        assertThat(helpText, containsString("DESCRIPTION"));

        for (final QueryFlag queryFlag : QueryFlag.values()) {
            if (!HelpQueryExecutor.SKIPPED.contains(queryFlag)) {
                assertThat(helpText, containsString(queryFlag.toString()));
            }
        }

        for (final String line : Splitter.on('\n').split(helpText)) {
            if (line.length() > 0) {
                assertThat(line, startsWith("%"));
            }
        }

        assertThat(helpText, containsString("RIPE Database Reference Manual"));
    }
}
