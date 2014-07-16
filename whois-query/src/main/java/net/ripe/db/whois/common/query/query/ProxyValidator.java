package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class ProxyValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public ProxyValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        if (query.hasProxy() && !query.isProxyValid()) {
            messages.add(queryMessages.malformedQuery());
        }
    }
}
