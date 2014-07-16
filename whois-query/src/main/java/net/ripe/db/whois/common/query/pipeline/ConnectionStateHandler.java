package net.ripe.db.whois.common.query.pipeline;

import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.query.Query;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;

public class ConnectionStateHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {

    static final ChannelBuffer NEWLINE = ChannelBuffers.wrappedBuffer(new byte[]{'\n'});

    private final QueryMessages queryMessages;

    private boolean keepAlive;
    private boolean closed;

    public ConnectionStateHandler(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        if (closed) {
            return;
        }

        final Query query = (Query) e.getMessage();
        final Channel channel = e.getChannel();


        if (keepAlive && query.hasOnlyKeepAlive()) {
            channel.close();
            return;
        }

        if (query.hasKeepAlive()) {
            keepAlive = true;
        }

        if (query.hasOnlyKeepAlive()) {
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
        } else {
            ctx.sendUpstream(e);
        }
    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            if (keepAlive && !((QueryCompletedEvent) e).isForceClose()) {
                channel.write(NEWLINE);
                channel.write(queryMessages.termsAndConditions());
            } else {
                closed = true;
                channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE);
            }
        }
    }
}
