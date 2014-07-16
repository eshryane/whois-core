package net.ripe.db.whois.common.query.pipeline;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.query.acl.AccessControlListManager;
import net.ripe.db.whois.common.query.query.Query;
import net.ripe.db.whois.common.query.query.QueryComponent;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;

@Component
@ChannelHandler.Sharable
public class QueryDecoder extends OneToOneDecoder {

    private final AccessControlListManager accessControlListManager;
    private final QueryComponent queryComponent;

    @Autowired
    public QueryDecoder(final AccessControlListManager accessControlListManager, final QueryComponent queryComponent) {
        this.accessControlListManager = accessControlListManager;
        this.queryComponent = queryComponent;
    }

    @Override
    protected Object decode(final ChannelHandlerContext ctx, final Channel channel, final Object msg) {
        final Query query = queryComponent.parse((String) msg, Query.Origin.LEGACY, isTrusted(channel));

        for (final Message warning : query.getWarnings()) {
            channel.write(warning);
        }

        return query;
    }

    private boolean isTrusted(final Channel channel) {
        return accessControlListManager.isTrusted(((InetSocketAddress)channel.getRemoteAddress()).getAddress());
    }
}
