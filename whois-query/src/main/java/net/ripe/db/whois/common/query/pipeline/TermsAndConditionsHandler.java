package net.ripe.db.whois.common.query.pipeline;

import net.ripe.db.whois.common.query.QueryMessages;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@ChannelHandler.Sharable
public class TermsAndConditionsHandler extends SimpleChannelUpstreamHandler {

    private final QueryMessages queryMessages;

    @Autowired
    public TermsAndConditionsHandler(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) {
        e.getChannel().write(queryMessages.termsAndConditions());

        ctx.sendUpstream(e);
    }
}
