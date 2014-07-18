package net.ripe.db.whois.query;

import java.io.OutputStream;

/**
 * Created by yogesh on 7/17/14.
 */
public interface IQueryResponsePublisher {
    void publish(IQueryResponse queryResponse);
}
