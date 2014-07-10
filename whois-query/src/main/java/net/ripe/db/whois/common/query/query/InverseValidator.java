package net.ripe.db.whois.common.query.query;

import net.ripe.db.whois.common.Messages;

class InverseValidator implements QueryValidator {
    @Override
    public void validate(final Query query, final Messages messages) {
        if (query.isInverse()) {
            final String auth = query.getSearchValue().toUpperCase();
            if (auth.startsWith("MD5-PW ")) {
                messages.add(net.ripe.db.whois.common.query.QueryMessages.inverseSearchNotAllowed());
            }
        }
    }
}
