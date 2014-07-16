package net.ripe.db.whois.common.query.pipeline;

import net.ripe.db.whois.common.query.QueryMessages;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;

public class ServedByHandler implements ChannelDownstreamHandler {
    private final String version;
    private final QueryMessages queryMessages;

    public ServedByHandler(final String version, final QueryMessages queryMessages) {
        this.version = version;
        this.queryMessages = queryMessages;
    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        if (e instanceof QueryCompletedEvent) {
            e.getChannel().write(queryMessages.servedByNotice(version));
        }

        ctx.sendDownstream(e);
    }
}
