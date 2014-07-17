package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.QueryException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TagValidatorTest {
    private Messages messages;
    @Mock private QueryMessages queryMessages;
    @InjectMocks private TagValidator subject;

    @Before
    public void setup() {
        messages = new Messages();

        when(queryMessages.invalidCombinationOfFlags(any(CharSequence.class), any(CharSequence.class))).thenReturn(new Message(Messages.Type.ERROR, ""));
    }

    @Ignore("TODO: [ES] move to integration test - new Query() is not detecting invalid combination")
    @Test
    public void both_filter_tag_include_and_exclude() {
        try {
            subject.validate(new Query("--filter-tag-include unref --filter-tag-exclude unref TEST-MNT", Query.Origin.LEGACY, false, queryMessages), messages);
            fail();
        } catch (QueryException e) {
            assertThat(e.getMessage(), containsString(queryMessages.invalidCombinationOfFlags("--filter-tag-include (unref)", "--filter-tag-exclude (unref)").toString()));
        }
    }

    @Test
    public void both_filter_tag_include_and_exclude_different_arguments() {
        subject.validate(new Query("--filter-tag-include foo --filter-tag-exclude unref TEST-MNT", Query.Origin.LEGACY, false, queryMessages), messages);
    }

    @Test
    public void filter_tag_include_correct() {
        subject.validate(new Query("--filter-tag-include unref TEST-MNT", Query.Origin.LEGACY, false, queryMessages), messages);
    }

    @Test
    public void filter_tag_exclude_correct() {
        subject.validate(new Query("--filter-tag-exclude unref TEST-MNT", Query.Origin.LEGACY, false, queryMessages), messages);
    }
}
