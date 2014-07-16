package net.ripe.db.whois.common.query.planner;


import net.ripe.db.whois.common.collect.IterableTransformer;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.domain.MessageObject;
import net.ripe.db.whois.common.query.executor.decorators.ResponseDecorator;
import net.ripe.db.whois.common.query.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Deque;
import java.util.EnumSet;

@Component
class AbuseCInfoDecorator implements ResponseDecorator {
    private static final EnumSet<ObjectType> ABUSE_LOOKUP_OBJECT_TYPES = EnumSet.of(ObjectType.INETNUM, ObjectType.INET6NUM, ObjectType.AUT_NUM);

    private final AbuseCFinder abuseCFinder;
    private final SourceContext sourceContext;
    private final QueryMessages queryMessages;

    @Autowired
    public AbuseCInfoDecorator(final AbuseCFinder abuseCFinder, SourceContext sourceContext, final QueryMessages queryMessages) {
        this.abuseCFinder = abuseCFinder;
        this.sourceContext = sourceContext;
        this.queryMessages = queryMessages;
    }

    @Override
    public Iterable<? extends ResponseObject> decorate(Query query, Iterable<? extends ResponseObject> input) {
        if (query.via(Query.Origin.REST) || query.isBriefAbuseContact() || !sourceContext.isMain()) {
            return input;
        }

        return new IterableTransformer<ResponseObject>(input) {
            @Override
            public void apply(ResponseObject input, Deque<ResponseObject> result) {
                if (!(input instanceof RpslObject)) {
                    result.add(input);
                    return;
                }

                final RpslObject object = (RpslObject) input;

                if (!ABUSE_LOOKUP_OBJECT_TYPES.contains(object.getType())) {
                    result.add(input);
                    return;
                }

                final String abuseContact = abuseCFinder.getAbuseContact(object);

                if (abuseContact != null) {
                    result.add(new MessageObject(queryMessages.abuseCShown(object.getKey(), abuseContact)));
                } else {
                    result.add(new MessageObject(queryMessages.abuseCNotRegistered(object.getKey())));
                }

                result.add(input);
                return;
            }
        };
    }
}
