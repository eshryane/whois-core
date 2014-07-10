package net.ripe.db.whois.internal;

import com.google.common.base.Stopwatch;
import net.ripe.db.whois.api.httpserver.JettyBootstrap;
import net.ripe.db.whois.common.Slf4JLogConfiguration;
import net.ripe.db.whois.common.profiles.WhoisProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

@Component
public class InternalServer {
    private static final Logger LOGGER = LoggerFactory.getLogger(InternalServer.class);

    private final JettyBootstrap jettyBootstrap;

    @Autowired
    public InternalServer(final JettyBootstrap jettyBootstrap) {
        this.jettyBootstrap = jettyBootstrap;
    }

    public static void main(final String[] args) {
        Slf4JLogConfiguration.init();

        final Stopwatch stopwatch = Stopwatch.createStarted();

        final ClassPathXmlApplicationContext applicationContext = WhoisProfile.initContextWithProfile("applicationContext-internal.xml", WhoisProfile.DEPLOYED);

        final InternalServer internalServer = applicationContext.getBean(InternalServer.class);
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                internalServer.stop();
            }
        });

        internalServer.start();

        LOGGER.info("Whois internal server started in {}", stopwatch.stop());
    }

    public void start() {
        LOGGER.info("Initializing: {}", jettyBootstrap);
        jettyBootstrap.start();
    }

    public void stop() {
        try {
            jettyBootstrap.stop(false);
        } catch (final RuntimeException e) {
            LOGGER.error("Stopping: {}", jettyBootstrap, e);
        }
    }
}
