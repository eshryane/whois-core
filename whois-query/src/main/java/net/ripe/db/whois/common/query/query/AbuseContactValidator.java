package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.rpsl.attrs.AutNum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class AbuseContactValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public AbuseContactValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        if (!query.isBriefAbuseContact()) {
            return;
        }

        if (query.getIpKeyOrNull() == null) {
            try {
                AutNum.parse(query.getSearchValue());
            } catch (final Exception ignored) {
                messages.add(queryMessages.malformedQuery());
            }
        }
    }
}
