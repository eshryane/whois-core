package net.ripe.db.whois.common.query.query;

import joptsimple.OptionException;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

// TODO: [ES] refactor
@Component
public class QueryComponent {

    private final QueryMessages queryMessages;
    private final List<QueryValidator> queryValidators;

    @Autowired
    public QueryComponent(final QueryMessages queryMessages, final List<QueryValidator> queryValidators) {
        this.queryMessages = queryMessages;
        this.queryValidators = queryValidators;
    }

    public Query parse(final String args) {
        return parse(args, Query.Origin.LEGACY, false);
    }

    public Query parse(final String args, final Query.Origin origin, final boolean trusted) {
        try {
            final Query query = new Query(args.trim(), origin, trusted, queryMessages);

            for (final QueryValidator queryValidator : queryValidators) {
                queryValidator.validate(query, query.getMessages());
            }

            final Collection<Message> errors = query.getMessages().getMessages(Messages.Type.ERROR);
            if (!errors.isEmpty()) {
                throw new QueryException(QueryCompletionInfo.PARAMETER_ERROR, errors);
            }

            return query;
        } catch (OptionException e) {
            throw new QueryException(QueryCompletionInfo.PARAMETER_ERROR, queryMessages.malformedQuery());
        }
    }

    public Query parse(final String args, final List<String> passwords, final boolean trusted) {
        final Query query = parse(args, Query.Origin.REST, trusted);
        query.setPasswords(passwords);
        return query;
    }


}
