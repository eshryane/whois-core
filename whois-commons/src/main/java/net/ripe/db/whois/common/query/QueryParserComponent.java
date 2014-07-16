package net.ripe.db.whois.common.query;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

// TODO: [ES] refactor
@Component
public class QueryParserComponent {

    private final QueryMessages queryMessages;

    @Autowired
    public QueryParserComponent(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    public QueryParser parse(final String query) {
        return new QueryParser(query, queryMessages);
    }
}
