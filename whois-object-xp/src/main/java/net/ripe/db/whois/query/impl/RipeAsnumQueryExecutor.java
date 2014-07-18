package net.ripe.db.whois.query.impl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.query.IQuery;
import net.ripe.db.whois.query.IQueryExecutor;
import net.ripe.db.whois.query.IQueryParser;
import net.ripe.db.whois.query.IQueryResponse;
import org.apache.commons.cli.*;

import java.util.Map;

/**
 * Created by yogesh on 7/17/14.
 */
public class RipeAsnumQueryExecutor implements IQueryExecutor, IQuery {

    private Map<String,String> optionValueMap = Maps.newHashMap();

    @Override
    public IQueryResponse execute(IQuery query) {
        return new IQueryResponse(){
            @Override
            public String toString() {
                return "Hello there!";
            }
        };
    }

    @Override
    public void setArgValue(String key, String value) {
        optionValueMap.put(key, value);
    }

    @Override
    public String getArgValue(String key) {
        return optionValueMap.get(key);
    }
}
