package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;

class ProxyValidator implements QueryValidator {
    @Override
    public void validate(final Query query, final Messages messages) {
        if (query.hasProxy() && !query.isProxyValid()) {
            messages.add(QueryMessages.malformedQuery());
        }
    }
}
