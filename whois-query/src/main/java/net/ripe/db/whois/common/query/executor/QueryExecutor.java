package net.ripe.db.whois.common.query.executor;

import net.ripe.db.whois.common.query.domain.ResponseHandler;
import net.ripe.db.whois.common.query.query.Query;

public interface QueryExecutor {
    boolean isAclSupported();

    boolean supports(Query query);

    void execute(Query query, ResponseHandler responseHandler);
}
