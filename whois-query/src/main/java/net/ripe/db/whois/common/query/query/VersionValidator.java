package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static net.ripe.db.whois.common.query.query.Query.Origin.INTERNAL;

@Component
class VersionValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public VersionValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        if ((query.isVersionList() || query.isObjectVersion()) && !query.via(INTERNAL)) {
            if (query.hasObjectTypesSpecified()) {
                for (ObjectType type : query.getObjectTypes()) {
                    // We don't allow person/role object history
                    if (type == ObjectType.PERSON || type == ObjectType.ROLE) {
                        messages.add(queryMessages.unsupportedVersionObjectType());
                    }
                }
            }
        }
    }
}
