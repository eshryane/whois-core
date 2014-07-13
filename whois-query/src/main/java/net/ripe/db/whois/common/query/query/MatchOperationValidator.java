package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.ip.IpInterval;
import net.ripe.db.whois.common.ip.Ipv4Resource;
import net.ripe.db.whois.common.ip.Ipv6Resource;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.query.QueryMessages;

class MatchOperationValidator implements QueryValidator {
    @Override
    public void validate(final Query query, final Messages messages) {
        final Query.MatchOperation matchOperation = query.matchOperation();

        if (query.hasIpFlags() && query.getIpKeyOrNull() == null) {
            messages.add(QueryMessages.uselessIpFlagPassed());
            return;
        }

        if (matchOperation == Query.MatchOperation.MATCH_FIRST_LEVEL_MORE_SPECIFIC || matchOperation == Query.MatchOperation.MATCH_ALL_LEVELS_MORE_SPECIFIC) {
            final IpInterval<?> ipKey = query.getIpKeyOrNull();
            if (ipKey == null) {
                return;
            }

            final IpInterval<?> maxRange = (ipKey.getVersion() == 4) ? Ipv4Resource.MAX_RANGE : Ipv6Resource.MAX_RANGE;
            if (maxRange.equals(ipKey)) {
                messages.add(QueryMessages.illegalRange());
            }
        }
    }
}
