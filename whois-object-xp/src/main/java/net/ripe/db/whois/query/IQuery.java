package net.ripe.db.whois.query;

/**
 * Created by yogesh on 7/17/14.
 */
public interface IQuery {

    void setKey(String key);
    String getKey();

    void setOptionValue(String key, String value);
    String getOptionValue(String key);
}
