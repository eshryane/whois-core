package net.ripe.db.whois.query.impl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.query.IQuery;
import net.ripe.db.whois.query.IQueryExecutor;
import net.ripe.db.whois.query.IQueryResponse;

import java.util.Map;

/**
 * Created by yogesh on 7/17/14.
 */
public class RipeAsnumQueryExecutor implements IQueryExecutor, IQuery {

    private Map<String,String> optionValueMap = Maps.newHashMap();

    private String key;

    @Override
    public IQueryResponse execute(IQuery query) {
        return new IQueryResponse(){
            @Override
            public String toString() {
                return "Hello there! Looking for " + key + "?";
            }
        };
    }

    @Override
    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public void setOptionValue(String key, String value) {
        optionValueMap.put(key, value);
    }

    @Override
    public String getOptionValue(String key) {
        return optionValueMap.get(key);
    }

    @Override
    public boolean supports(Object key) {
        return key.toString().trim().toUpperCase().startsWith("AS-");
    }
}
