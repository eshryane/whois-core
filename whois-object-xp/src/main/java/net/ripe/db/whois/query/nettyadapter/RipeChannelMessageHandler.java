package net.ripe.db.whois.query.nettyadapter;

import net.ripe.db.whois.query.IQueryResponse;
import net.ripe.db.whois.query.IQueryResponsePublisher;
import net.ripe.db.whois.query.impl.RipeQueryHandler;
import org.jboss.netty.channel.*;

import javax.inject.Inject;

/**
 * Created by yogesh on 7/18/14.
 */
public class RipeChannelMessageHandler extends SimpleChannelUpstreamHandler implements IQueryResponsePublisher {

    @Inject
    private RipeQueryHandler ripeQueryHandler;

    private Channel channel;

    private boolean closed = false;

    public RipeChannelMessageHandler() {
        super();
        ripeQueryHandler.registerPublisher(this);
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent event) throws Exception {
        super.messageReceived(ctx, event);

        final String query = (String) event.getMessage();
        ripeQueryHandler.handle(query);

        channel = event.getChannel();
    }

    @Override
    public void channelClosed(final ChannelHandlerContext ctx, final ChannelStateEvent e) throws Exception {
        closed = true;
        super.channelClosed(ctx, e);
    }

    @Override
    public void publish(IQueryResponse queryResponse) {
        if (closed) { // Prevent hammering a closed channel
            //throw new QueryException(QueryCompletionInfo.DISCONNECTED);
        } else {
            channel.write(queryResponse.toString());
        }
        //channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
    }
}
