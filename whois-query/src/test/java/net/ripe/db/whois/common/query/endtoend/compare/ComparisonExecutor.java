package net.ripe.db.whois.common.query.endtoend.compare;

import net.ripe.db.whois.common.domain.ResponseObject;

import java.io.IOException;
import java.util.List;

public interface ComparisonExecutor {
    List<ResponseObject> getResponse(final String query) throws IOException;
}
