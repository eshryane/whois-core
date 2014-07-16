package net.ripe.db.whois.common.query.planner;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.query.query.Query;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Collections;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class RelatedToDecoratorTest {
    @Mock private RpslObjectDao rpslObjectDao;
    @Mock private QueryMessages queryMessages;
    @InjectMocks private RelatedToDecorator subject;

    @Test
    public void appliesToQuery_empty() {
        assertThat(subject.appliesToQuery(new Query("foo", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void appliesToQuery_related() {
        assertThat(subject.appliesToQuery(new Query("-T inetnum 10.0.0.0", Query.Origin.LEGACY, false, queryMessages)), is(true));
    }

    @Test
    public void appliesToQuery_not_related() {
        assertThat(subject.appliesToQuery(new Query("-r -T inetnum 10.0.0.0", Query.Origin.LEGACY, false, queryMessages)), is(false));
    }

    @Test
    public void decorate() {
        RpslObject rpslObject = RpslObject.parse("mntner: DEV-MNT");
        subject.decorate(new Query("DEV-MNT", Query.Origin.LEGACY, false, queryMessages), rpslObject);

        verify(rpslObjectDao, times(1)).relatedTo(rpslObject, Collections.<ObjectType>emptySet());
    }

    @Test
    public void decorate_no_personal() {
        RpslObject rpslObject = RpslObject.parse("mntner: DEV-MNT");
        subject.decorate(new Query("--no-personal DEV-MNT", Query.Origin.LEGACY, false, queryMessages), rpslObject);

        verify(rpslObjectDao, times(1)).relatedTo(rpslObject, Sets.newEnumSet(Lists.newArrayList(ObjectType.PERSON, ObjectType.ROLE), ObjectType.class));
    }

}
