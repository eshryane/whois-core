package net.ripe.db.whois.common.query.integration;

import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.executor.CaptureResponseHandler;
import net.ripe.db.whois.common.query.executor.SearchQueryExecutor;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.query.query.QueryComponent;
import net.ripe.db.whois.common.query.support.AbstractQueryIntegrationTest;
import net.ripe.db.whois.common.rpsl.AttributeType;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@Category(IntegrationTest.class)
public class SearchQueryExecutorTestIntegration extends AbstractQueryIntegrationTest {

    @Autowired QueryComponent queryComponent;
    @Autowired SearchQueryExecutor subject;

//    @Before
//    public void setUp() throws Exception {
//        when(rpslObjectSearcher.search(any(Query.class))).thenReturn((Iterable)Collections.emptyList());
//        when(rpslResponseDecorator.getResponse(any(Query.class), any(Iterable.class))).thenAnswer(new Answer<Object>() {
//            @Override
//            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
//                return invocationOnMock.getArguments()[1];
//            }
//        });
//    }

    @Test
    public void all_attributes_handled() {
        for (final AttributeType attributeType : AttributeType.values()) {
            assertTrue(subject.supports(queryComponent.parse("-i " + attributeType.getName() + " query")));
        }
    }

    @Test(expected = QueryException.class)
    public void test_supports_no_attributes() {
        assertThat(subject.supports(queryComponent.parse("-i")), is(false));
    }

    @Test
    public void test_supports_inverse_with_filter() {
        assertThat(subject.supports(queryComponent.parse("-T inetnum -i mnt-by aardvark-mnt")), is(true));
    }

    @Test
    public void test_supports_inverse_recursive() {
        assertThat(subject.supports(queryComponent.parse("-i mnt-by aardvark-mnt")), is(true));
    }

    @Test
    public void test_supports_inverse() {
        assertThat(subject.supports(queryComponent.parse("-r -i mnt-by aardvark-mnt")), is(true));
    }

    @Test
    public void test_supports_inverse_multiple() {
        assertThat(subject.supports(queryComponent.parse("-r -i mnt-by,mnt-ref aardvark-mnt")), is(true));
    }

    @Test
    public void test_supports_inverse_multiple_unknown() {
        assertThat(subject.supports(queryComponent.parse("-r -i mnt-by,mnt-ref,mnt-lower aardvark-mnt")), is(true));
    }

    @Test
    public void unknown_source() {
        final Query query = queryComponent.parse("-s UNKNOWN 10.0.0.0");

        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);
//        verify(rpslObjectSearcher, never()).search(query);
//
//        assertThat(responseHandler.getResponseObjects(), hasSize(1));   // make sure that e.g. 'no results found' is not printed
//        assertThat(responseHandler.getResponseObjects().get(0), Matchers.<ResponseObject>is(new MessageObject(queryMessages.unknownSource("UNKNOWN"))));
    }

    @Test
    public void query_all_sources() {
//        when(sourceContext.getAllSourceNames()).thenReturn(ciSet("APNIC-GRS", "ARIN-GRS"));

        final Query query = queryComponent.parse("--all-sources 10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);


//        sourceContext.getCurrentSource()
//
//
//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext, times(2)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(2)).search(query);
    }

    @Test
    public void query_sources() {
        final Query query = queryComponent.parse("--sources APNIC-GRS,ARIN-GRS 10.0.0.0");

        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext, times(2)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(2)).search(query);
    }

    @Test
    public void query_sources_and_additional() {
//        when(sourceContext.getAllSourceNames()).thenReturn(ciSet("APNIC-GRS", "ARIN-GRS"));

        final Query query = queryComponent.parse("--all-sources --sources RIPE 10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("RIPE"));
//        verify(sourceContext, times(3)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(3)).search(query);
    }

    @Test
    public void query_resources() {
//        when(sourceContext.getGrsSourceNames()).thenReturn(ciSet("APNIC-GRS", "ARIN-GRS"));

        final Query query = queryComponent.parse("--resource 10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext, times(2)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(2)).search(query);
    }

    @Test
    public void query_all_sources_filters_virtual_sources() {
//        when(sourceContext.getAllSourceNames()).thenReturn(ciSet("RIPE", "RIPE-GRS", "APNIC-GRS", "ARIN-GRS"));
//        when(sourceContext.isVirtual(any(CIString.class))).thenAnswer(new Answer<Boolean>() {
//            @Override
//            public Boolean answer(InvocationOnMock invocation) throws Throwable {
//                final Object[] arguments = invocation.getArguments();
//                return (ciString("RIPE-GRS").equals(arguments[0]));
//            }
//        });

        final Query query = queryComponent.parse("--all-sources 10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext, never()).setCurrent(Source.slave("RIPE-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("RIPE"));
//        verify(sourceContext, times(3)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(3)).search(query);
    }

    @Test
    public void query_no_source_specified() {
//        when(sourceContext.getWhoisSlaveSource()).thenReturn(Source.slave("RIPE"));

        final Query query = queryComponent.parse("10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("RIPE"));
//        verify(sourceContext).removeCurrentSource();
//        verify(rpslObjectSearcher).search(query);
    }

    @Test
    public void no_results_found_gives_message() {
        final Query query = queryComponent.parse("-s RIPE 10.0.0.0");

        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(rpslObjectSearcher).search(query);
//        verify(rpslResponseDecorator).getResponse(eq(query), any(Iterable.class));
//
//        assertThat(responseHandler.getResponseObjects(), contains((ResponseObject) new MessageObject(queryMessages.noResults("RIPE").toString())));
    }

    @Test
    public void query_additional_sources() {
//        when(sourceContext.getAdditionalSourceNames()).thenReturn(ciSet("APNIC-GRS", "ARIN-GRS"));
//        when(sourceContext.getWhoisSlaveSource()).thenReturn(Source.slave("RIPE"));

        final Query query = queryComponent.parse("10.0.0.0");
        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("RIPE"));
//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext, times(3)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(3)).search(query);
    }

    @Test
    public void query_sources_not_additional() {
//        when(sourceContext.getAdditionalSourceNames()).thenReturn(ciSet("RIPE", "APNIC-GRS", "ARIN-GRS"));

        final Query query = queryComponent.parse("--sources APNIC-GRS,ARIN-GRS 10.0.0.0");

        final CaptureResponseHandler responseHandler = new CaptureResponseHandler();
        subject.execute(query, responseHandler);

//        verify(sourceContext).setCurrent(Source.slave("APNIC-GRS"));
//        verify(sourceContext).setCurrent(Source.slave("ARIN-GRS"));
//        verify(sourceContext, times(2)).removeCurrentSource();
//        verify(rpslObjectSearcher, times(2)).search(query);
    }

}
