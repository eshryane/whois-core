package net.ripe.db.whois.query;

/**
 * Created by yogesh on 7/17/14.
 */
public interface IQueryExecutorFactory {
    IQueryExecutor getQueryExecutor(IQuery query);
}
