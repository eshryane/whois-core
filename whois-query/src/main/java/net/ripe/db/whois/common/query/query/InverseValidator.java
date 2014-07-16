package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class InverseValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public InverseValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        if (query.isInverse()) {
            final String auth = query.getSearchValue().toUpperCase();
            if (auth.startsWith("MD5-PW ")) {
                messages.add(queryMessages.inverseSearchNotAllowed());
            }
        }
    }
}
