package net.ripe.db.whois.query.impl;

import net.ripe.db.whois.query.IQuery;
import net.ripe.db.whois.query.IQueryExecutor;
import net.ripe.db.whois.query.IQueryResponse;

/**
 * Created by yogesh on 7/17/14.
 */
public class RipeHelpQueryExecutor implements IQueryExecutor, IQuery {

    private String usageText = null;

    @Override
    public IQueryResponse execute(IQuery query) {
        return new IQueryResponse(){
            @Override
            public String toString() {
                return usageText;
            }
        };
    }

    @Override
    public void setOptionValue(String key, String value) {
    }

    @Override
    public String getOptionValue(String key) {
        return null;
    }

    @Override
    public void setKey(String key) {
    }

    @Override
    public String getKey() {
        return null;
    }

    public void setHelpText(String usageText) {
        this.usageText = usageText;
    }

    @Override
    public boolean supports(Object key) {
        return key == null || "help".equals(key.toString().trim().toLowerCase());
    }
}
