package net.ripe.db.whois.query;

import java.util.Collection;

/**
 * Created by yogesh on 7/18/14.
 */
public abstract class AbstractQueryHandler implements IQueryHandler {

    /**
     * Template method
     * @param query
     */
    @Override
    public void handle(String query) {

        // Parse
        String modifiedQuery = modifyQuery(query);
        IQuery parsedQuery = getQueryParser().parse(modifiedQuery);

        // Execute
        IQuery modifiedParsedQuery = modifyParsedQuery(parsedQuery);
        IQueryExecutor queryExecutor = getQueryExecutorFactory().getQueryExecutor(modifiedParsedQuery);
        IQueryResponse queryResponse = queryExecutor.execute(modifiedParsedQuery);

        // Publish
        IQueryResponse modifiedQueryResponse = modifyQueryResponse(queryResponse);
        for (IQueryResponsePublisher queryResponsePublisher: getQueryResponsePublishers()) {
            queryResponsePublisher.publish(modifiedQueryResponse);
        }

    }


    abstract protected IQueryParser getQueryParser();

    abstract protected IQueryExecutorFactory getQueryExecutorFactory();

    abstract protected Collection<IQueryResponsePublisher> getQueryResponsePublishers();

    /**
     * Hook method
     * @param query
     * @return
     */
    protected String modifyQuery(String query) {
        return query;
    }

    /**
     * Hook method
     * @param parsedQuery
     * @return
     */
    protected IQuery modifyParsedQuery(IQuery parsedQuery) {
        return parsedQuery;
    }

    /**
     * Hook method
     * @param queryResponse
     * @return
     */
    protected IQueryResponse modifyQueryResponse(IQueryResponse queryResponse) {
        return queryResponse;
    }

}
