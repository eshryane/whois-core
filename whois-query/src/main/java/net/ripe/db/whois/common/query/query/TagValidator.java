package net.ripe.db.whois.common.query.query;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.query.QueryFlag;
import net.ripe.db.whois.common.query.QueryMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class TagValidator implements QueryValidator {

    private final QueryMessages queryMessages;

    @Autowired
    public TagValidator(final QueryMessages queryMessages) {
        this.queryMessages = queryMessages;
    }

    @Override
    public void validate(final Query query, final Messages messages) {
        if (query.hasOption(QueryFlag.FILTER_TAG_INCLUDE) && query.hasOption(QueryFlag.FILTER_TAG_EXCLUDE)) {
            final Sets.SetView<String> intersection = Sets.intersection(query.getOptionValues(QueryFlag.FILTER_TAG_INCLUDE),
                    query.getOptionValues(QueryFlag.FILTER_TAG_EXCLUDE));

            if (!intersection.isEmpty()) {
                final String args = " (" + Joiner.on(',').join(intersection.iterator()) + ")";
                messages.add(queryMessages.invalidCombinationOfFlags(
                        QueryFlag.FILTER_TAG_INCLUDE.toString() + args,
                        QueryFlag.FILTER_TAG_EXCLUDE.toString() + args));
            }
        }
    }
}
