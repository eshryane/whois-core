package net.ripe.db.whois.common.query.executor;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.MessageObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class MessageObjectTest {

    @Mock private QueryMessages queryMessages;
    private MessageObject subject = new MessageObject("message");

    @Test
    public void equals_and_hashCode() throws Exception {
        MessageObject same = new MessageObject(subject.toString());
        MessageObject other = new MessageObject(subject.toString() + "Other");

        assertThat("self", subject, is(subject));
        assertThat("same", subject, is(same));
        assertFalse("null", subject.equals(null));
        assertFalse("type", subject.equals(1));
        assertFalse("other", subject.equals(other));

        final Message message = queryMessages.timeout();
        assertThat("fromMessage", new MessageObject(message), is(new MessageObject(message)));

        assertThat("hashCode self", subject.hashCode(), is(subject.hashCode()));
        assertThat("hashCode same", subject.hashCode(), is(same.hashCode()));
    }
}
