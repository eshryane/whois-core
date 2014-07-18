package net.ripe.db.whois.query.nettyadapter;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;

/**
 * Created by yogesh on 7/18/14.
 */
@ChannelHandler.Sharable
public class RipeQueryDecoder extends OneToOneDecoder {

    @Override
    protected Object decode(ChannelHandlerContext channelHandlerContext, Channel channel, Object msg) throws Exception {
        return (String) msg;
    }
}
