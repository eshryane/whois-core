package net.ripe.db.whois.common.query.acl;

import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.core.OperationTimeoutException;
import net.ripe.db.whois.common.profiles.DeployedProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.net.InetAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@DeployedProfile
@Primary
@Component
public class HazelcastPersonalObjectAccounting implements PersonalObjectAccounting {
    private static final Logger LOGGER = LoggerFactory.getLogger(HazelcastPersonalObjectAccounting.class);

    private static IMap<InetAddress, Integer> counterMap;

    private static volatile HazelcastInstance instance;

    static synchronized void startHazelcast() {
        if (instance != null) {
            throw new IllegalStateException("Hazelcast already started");
        }

        instance = Hazelcast.newHazelcastInstance(null);
        counterMap = instance.getMap("queriedPersonal");
    }

    static void shutdownHazelcast() {
        LOGGER.debug("Shutting down hazelcast instance");

        instance.getLifecycleService().shutdown();
        instance = null;
    }

    @PostConstruct
    public void startService() {
        startHazelcast();
    }

    @PreDestroy
    public void stopService() {
        shutdownHazelcast();
    }

    @Override
    public int getQueriedPersonalObjects(final InetAddress remoteAddress) {
        Integer count = null;
        try {
            count = counterMap.get(remoteAddress);
        } catch (OperationTimeoutException e) {
            // prevents user from seeing "internal server error"
        }

        if (count == null) {
            return 0;
        }

        return count;
    }

    @Override
    public int accountPersonalObject(final InetAddress remoteAddress, final int amount) {
        try {
            counterMap.lock(remoteAddress);
            Integer count = counterMap.getAsync(remoteAddress).get(3, TimeUnit.SECONDS);

            if (count == null) {
                count = amount;
            } else {
                count += amount;
            }

            counterMap.putAsync(remoteAddress, count).get(3, TimeUnit.SECONDS);
            return count;

        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.info("Unable to account personal object, allowed by default");
        } finally {
            if (counterMap.isLocked(remoteAddress)) {
                counterMap.unlock(remoteAddress);
            }
        }

        return 0;
    }

    @Override
    public void resetAccounting() {
        LOGGER.debug("Reset person object counters ({} entries)", counterMap.size());
        counterMap.clear();
    }
}
