package net.ripe.db.whois.common.query.pipeline;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.pipeline.ChannelUtil;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.QueryMessages;
import org.jboss.netty.channel.*;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.timeout.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Collections;

public class ExceptionHandler extends SimpleChannelUpstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExceptionHandler.class);

    private QueryMessages queryMessages;
    private String query;

    public ExceptionHandler(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        query = e.getMessage().toString();

        ctx.sendUpstream(e);
    }

    @Override
    public void exceptionCaught(final ChannelHandlerContext ctx, final ExceptionEvent event) {
        final Throwable cause = event.getCause();
        LOGGER.debug("Caught exception", cause);

        final Channel channel = event.getChannel();
        if (cause instanceof ClosedChannelException) {
            LOGGER.debug("Channel closed", cause);
        } else if (cause instanceof QueryException) {
            handleException(channel, ((QueryException) cause).getMessages(), ((QueryException) cause).getCompletionInfo());
        } else if (cause instanceof TimeoutException) {
            handleException(channel, Collections.singletonList(queryMessages.timeout()), QueryCompletionInfo.EXCEPTION);
        } else if (cause instanceof TooLongFrameException) {
            handleException(channel, Collections.singletonList(queryMessages.inputTooLong()), QueryCompletionInfo.EXCEPTION);
        } else if (cause instanceof IOException) {
            handleException(channel, Collections.<Message>emptyList(), QueryCompletionInfo.EXCEPTION);
        } else {
            LOGGER.error("Caught exception on channel id = {}, from = {} for query = {}",
                    channel.getId(),
                    ChannelUtil.getRemoteAddress(channel),
                    query,
                    cause);

            handleException(channel, Collections.singletonList(queryMessages.internalErroroccurred()), QueryCompletionInfo.EXCEPTION);
        }
    }

    private void handleException(final Channel channel, final Iterable<Message> messages, final QueryCompletionInfo completionInfo) {
        if (channel.isOpen()) {
            for (final Message message : messages) {
                channel.write(message);
            }
        }

        channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel, completionInfo));
    }
}
