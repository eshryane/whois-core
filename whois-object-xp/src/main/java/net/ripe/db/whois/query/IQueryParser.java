package net.ripe.db.whois.query;

/**
 * Created by yogesh on 7/17/14.
 */
public interface IQueryParser {
    IQuery parse(String query);
}
