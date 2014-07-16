package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.ip.IpInterval;
import net.ripe.db.whois.common.ip.Ipv4Resource;
import net.ripe.db.whois.common.ip.Ipv6Resource;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.query.QueryMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class MatchOperationValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public MatchOperationValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        final Query.MatchOperation matchOperation = query.matchOperation();

        if (query.hasIpFlags() && query.getIpKeyOrNull() == null) {
            messages.add(queryMessages.uselessIpFlagPassed());
            return;
        }

        if (matchOperation == Query.MatchOperation.MATCH_FIRST_LEVEL_MORE_SPECIFIC || matchOperation == Query.MatchOperation.MATCH_ALL_LEVELS_MORE_SPECIFIC) {
            final IpInterval<?> ipKey = query.getIpKeyOrNull();
            if (ipKey == null) {
                return;
            }

            final IpInterval<?> maxRange = AttributeType.INETNUM.equals(ipKey.getAttributeType()) ? Ipv4Resource.MAX_RANGE : Ipv6Resource.MAX_RANGE;
            if (maxRange.equals(ipKey)) {
                messages.add(queryMessages.illegalRange());
            }
        }
    }
}
