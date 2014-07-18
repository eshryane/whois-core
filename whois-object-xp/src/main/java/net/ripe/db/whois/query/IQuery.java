package net.ripe.db.whois.query;

/**
 * Created by yogesh on 7/17/14.
 */
public interface IQuery {
    void setArgValue(String key, String value);
    String getArgValue(String key);
}
