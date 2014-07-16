package net.ripe.db.whois.common.query.planner;


import com.google.common.base.Function;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.rpsl.ObjectMessages;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.query.domain.MessageObject;
import net.ripe.db.whois.common.query.QueryMessages;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;

class SyntaxFilterFunction implements Function<ResponseObject, Iterable<? extends ResponseObject>> {
    private final QueryMessages queryMessages;
    private final boolean isValidSyntaxQuery;

    SyntaxFilterFunction(final QueryMessages queryMessages, final boolean validSyntaxQuery) {
        this.queryMessages = queryMessages;
        this.isValidSyntaxQuery = validSyntaxQuery;
    }

    @Override
    public Iterable<? extends ResponseObject> apply(@Nullable final ResponseObject input) {
        if (input instanceof RpslObject) {
            final RpslObject object = (RpslObject) input;

            if (!validSyntax(object) && isValidSyntaxQuery) {
                return Arrays.asList(new MessageObject(queryMessages.invalidSyntax(object.getKey())));
            }
            else if (validSyntax(object) && !isValidSyntaxQuery) {
                return Arrays.asList(new MessageObject(queryMessages.validSyntax(object.getKey())));
            }
        }
        return Collections.singletonList(input);
    }

    private boolean validSyntax(final RpslObject object) {
        final ObjectMessages objectMessages = ObjectTemplate.getTemplate(object.getType()).validate(object);
        return objectMessages.getErrorCount() == 0;
    }
}
