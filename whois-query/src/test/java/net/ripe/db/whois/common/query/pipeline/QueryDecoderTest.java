package net.ripe.db.whois.common.query.pipeline;

import com.google.common.collect.Lists;
import com.google.common.net.InetAddresses;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.acl.AccessControlListManager;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.query.query.QueryComponent;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class QueryDecoderTest {

    @Mock private Channel channelMock;
    @Mock private ChannelFuture channelFutureMock;
    @Mock private ChannelPipeline channelPipelineMock;
    @Mock private ChannelHandlerContext channelHandlerContextMock;
    @Mock private AccessControlListManager accessControlListManager;
    @Mock private QueryMessages queryMessages;
    @Mock private QueryComponent queryComponent;
    @InjectMocks private QueryDecoder subject;

    private List<Object> writtenBuffer = Lists.newArrayList();

    @Before
    public void setup() {
        when(channelMock.write(any(ChannelBuffer.class))).thenAnswer(new Answer<ChannelFuture>() {
            public ChannelFuture answer(InvocationOnMock invocation) throws Throwable {
                writtenBuffer.add(invocation.getArguments()[0]);
                return channelFutureMock;
            }
        });

        when(channelMock.getPipeline()).thenReturn(channelPipelineMock);
        when(channelHandlerContextMock.getPipeline()).thenReturn(channelPipelineMock);
        when(channelPipelineMock.getContext(QueryDecoder.class)).thenReturn(channelHandlerContextMock);
        when(accessControlListManager.isTrusted(any(InetAddress.class))).thenReturn(true);

        when(queryComponent.parse(any(String.class), any(Query.Origin.class), any(Boolean.class))).thenAnswer(new Answer<Query>() {
            @Override
            public Query answer(InvocationOnMock invocation) throws Throwable {
                return new Query(
                        (String)invocation.getArguments()[0],
                        (Query.Origin)invocation.getArguments()[1],
                        (Boolean)invocation.getArguments()[2],
                        queryMessages);
            }
        });

        when(queryMessages.malformedQuery()).thenReturn(new Message(Messages.Type.ERROR, ""));
    }

    @Ignore("TODO: [ES] convert to integration test")
    @Test(expected = QueryException.class)
    public void invalidProxyShouldThrowException() {
        new Query("-Vone,two,three -Tperson DW-RIPE", Query.Origin.LEGACY, false, queryMessages);
    }

    @Test
    public void validDecodedStringShouldReturnQuery() throws Exception {
        String queryString = "-Tperson DW-RIPE";
        Query expectedQuery = new Query(queryString, Query.Origin.LEGACY, false, queryMessages);

        when(channelMock.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddresses.forString("10.0.0.1"), 80));

        Query actualQuery = (Query) subject.decode(channelHandlerContextMock, channelMock, queryString);

        assertEquals(expectedQuery, actualQuery);
    }

    @Test
    public void invalidOptionQuery() {
        String queryString = "-Yperson DW-RIPE";
        when(channelMock.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddresses.forString("10.0.0.1"), 80));

        try {
            subject.decode(null, channelMock, queryString);
            fail("Expected query exception");
        } catch (QueryException e) {
            assertThat(e.getCompletionInfo(), is(QueryCompletionInfo.PARAMETER_ERROR));
        }
    }

    @Ignore("TODO: [ES] convert to integration test")
    @Test
    public void invalidProxyQuery() throws Exception {
        String queryString = "-Vone,two,three DW-RIPE";
        when(channelMock.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddresses.forString("10.0.0.1"), 80));

        try {
            subject.decode(null, channelMock, queryString);
            fail("Expected query exception");
        } catch (QueryException e) {
            assertThat(e.getCompletionInfo(), is(QueryCompletionInfo.PARAMETER_ERROR));
        }
    }
}
