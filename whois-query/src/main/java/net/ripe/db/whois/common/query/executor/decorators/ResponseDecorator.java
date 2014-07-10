package net.ripe.db.whois.common.query.executor.decorators;

import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.query.query.Query;

public interface ResponseDecorator {
    Iterable<? extends ResponseObject> decorate(Query query, Iterable<? extends ResponseObject> input);
}
