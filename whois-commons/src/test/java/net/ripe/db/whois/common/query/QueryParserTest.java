package net.ripe.db.whois.common.query;

import net.ripe.db.whois.common.IllegalArgumentExceptionMessage;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class QueryParserTest {
    private QueryMessages queryMessages = mock(QueryMessages.class);
    private QueryParser subject;

    private QueryParser parseWithNewline(String input) {
        // [EB]: userinput will always be newline terminated
        return new QueryParser(input + "\n", queryMessages);
    }

    private void parse(String input) {
        subject = parseWithNewline(input);
    }


    @Test
    public void equals_hashcode() {
        parse("-Tperson Truus");

        assertTrue(subject.equals(subject));
        assertThat(subject.hashCode(), is(subject.hashCode()));
        assertFalse(subject.equals(null));
        assertFalse(subject.equals(2L));

        QueryParser differentQuery = parseWithNewline("-Tperson joost");
        assertFalse(subject.equals(differentQuery));
        assertThat(subject.hashCode(), not(is(differentQuery.hashCode())));

        QueryParser sameQuery = parseWithNewline("-Tperson Truus");
        assertTrue(subject.equals(sameQuery));
        assertThat(subject.hashCode(), is(sameQuery.hashCode()));
    }

    @Test
    public void hasflags() {
        assertThat(new QueryParser("--abuse-contact 193.0.0.1", queryMessages).hasFlags(), is(true));
        assertThat(new QueryParser("-L 193.0.0.1", queryMessages).hasFlags(), is(true));
        assertThat(new QueryParser("193.0.0.1", queryMessages).hasFlags(), is(false));
    }

    @Test
    public void hasflags_invalid_option_supplied() {
        try {
            when(queryMessages.malformedQuery(any(String.class))).thenAnswer(new Answer<Message>() {
                @Override
                public Message answer(InvocationOnMock invocation) throws Throwable {
                    return new Message(Messages.Type.ERROR, "Invalid option: " + invocation.getArguments()[0]);
                }
            });
            new QueryParser("--this-is-an-invalid-flag", queryMessages).hasFlags();
            fail();
        } catch (IllegalArgumentExceptionMessage e) {
            assertThat(e.getExceptionMessage(), is(queryMessages.malformedQuery("Invalid option: --this-is-an-invalid-flag")));
        }
    }

}
