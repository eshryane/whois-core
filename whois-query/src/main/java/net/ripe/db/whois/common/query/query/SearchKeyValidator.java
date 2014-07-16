package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class SearchKeyValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public SearchKeyValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        // No search key required for queries below
        if (query.isHelp() || query.isTemplate() || query.isVerbose() || query.isSystemInfo() || query.hasOnlyKeepAlive()) {
            return;
        }

        if (query.getSearchValue().isEmpty()) {
            messages.add(queryMessages.noSearchKeySpecified());
        }

        // We don't check attributes for inverse queries, but search value is required
        if (query.isInverse()) {
            return;
        }

        if (query.getObjectTypes().isEmpty()) {
            messages.add(queryMessages.invalidSearchKey());
        }
    }
}
