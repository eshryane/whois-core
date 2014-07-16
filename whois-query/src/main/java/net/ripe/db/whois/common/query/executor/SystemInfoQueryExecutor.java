package net.ripe.db.whois.common.query.executor;

import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.MessageObject;
import net.ripe.db.whois.common.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.common.query.domain.QueryException;
import net.ripe.db.whois.common.query.domain.ResponseHandler;
import net.ripe.db.whois.common.query.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Set;

@Component
public class SystemInfoQueryExecutor implements QueryExecutor {
    private static final Set<ObjectType> ORDERED_TYPES = Sets.newTreeSet(ObjectType.COMPARATOR);

    static {
        Collections.addAll(ORDERED_TYPES, ObjectType.values());
    }

    @Value("${application.version}")
    private String version;

    private final SourceContext sourceContext;
    private final QueryMessages queryMessages;

    @Autowired
    public SystemInfoQueryExecutor(final SourceContext sourceContext, final QueryMessages queryMessages) {
        this.sourceContext = sourceContext;
        this.queryMessages = queryMessages;
    }

    @Override
    public boolean isAclSupported() {
        return false;
    }

    @Override
    public boolean supports(final Query query) {
        return query.isSystemInfo();
    }

    @Override
    public void execute(final Query query, final ResponseHandler responseHandler) {
        final Query.SystemInfoOption systemInfoOption = query.getSystemInfoOption();

        final String responseString;
        switch (systemInfoOption) {
            case VERSION:
                responseString = "% whois-server-" + version;
                break;
            case TYPES: {
                final StringBuilder builder = new StringBuilder();

                for (ObjectType type : ORDERED_TYPES) {
                    builder.append(type.getName());
                    builder.append('\n');
                }
                responseString = builder.toString();
                break;
            }
            case SOURCES: {
                StringBuilder builder = new StringBuilder();

                for (final CIString source : sourceContext.getAllSourceNames()) {
                    builder.append(String.format("%s:3:N:0-0\n", source));
                }
                responseString = builder.toString();
                break;
            }
            default:
                throw new QueryException(QueryCompletionInfo.PARAMETER_ERROR, queryMessages.malformedQuery());
        }

        responseHandler.handle(new MessageObject(responseString));
    }
}
