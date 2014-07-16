package net.ripe.db.whois.common.query;

import com.google.common.base.Joiner;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.QueryMessage;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Hosts;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.Locale;
import java.util.Set;

import static net.ripe.db.whois.common.Messages.Type;

@Component
public class QueryMessages {

    private static Logger LOGGER = LoggerFactory.getLogger(QueryMessages.class);

    private static final Joiner JOINER = Joiner.on(", ");

    private final MessageSource messageSource;

    @Autowired
    public QueryMessages(final MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    // solely used by port43 pipeline handler
    public Message termsAndConditions() {
        return createMessage(Type.INFO, "terms.and.conditions");
    }

    // solely used by port43 pipeline handler
    public Message servedByNotice(final CharSequence version) {
        return createMessage(Type.INFO, "served.by.notice", version, Hosts.getLocalHostName());
    }

    // solely used by text_export
    public Message termsAndConditionsDump() {
        return createMessage(Type.INFO, "terms.and.conditions.dump");
    }

    public Message relatedTo(final CharSequence key) {
        return createMessage(Type.INFO, "related.to", key);
    }

    public Message noPersonal() {
        return createMessage(Type.INFO, "personal.data.filtered", QueryFlag.NO_PERSONAL.getLongFlag());
    }

    public Message abuseCShown(final CharSequence key, final CharSequence value) {
        return createMessage(Type.INFO, "abuse.contact.shown", key, value);
    }

    public Message abuseCNotRegistered(final CharSequence key) {
        return createMessage(Type.INFO, "abuse.contact.not.registered", key);

    }

    public Message outputFilterNotice() {
        return createMessage(Type.INFO, "output.filter.notice");
    }

    public Message primaryKeysOnlyNotice() {
        return createMessage(Type.INFO, "primary.keys.only.notice");
    }

    public Message versionListStart(final CharSequence type, final CharSequence key) {
        return createMessage(Type.INFO, "version.list.start", type, key, QueryFlag.SHOW_VERSION);
    }

    public Message versionInformation(final int version, final boolean isCurrentVersion, final CIString key, final String operation, final VersionDateTime timestamp) {
        return createMessage(Type.INFO,
                "version.information",
                version,
                (isCurrentVersion ? "(current version) " : ""),
                key,
                operation,
                timestamp,
                QueryFlag.LIST_VERSIONS);
    }

    public Message versionDifferenceHeader(final int earlierVersion, final int laterVersion, final CIString key) {
        return createMessage(Type.INFO, "version.difference.header",
                earlierVersion,
                laterVersion,
                key);
    }

    public Message versionDeleted(final CharSequence deletionTime) {
        return createMessage(Type.INFO, "version.deleted", String.format("%-16s", deletionTime));
    }

    public Message versionPersonRole(final CharSequence type, final CharSequence key) {
        return createMessage(Type.INFO, "version.person.role", type, key);
    }

    public Message internalErroroccurred() {
        return createMessage(Type.INFO, "internal.error.occurred");
    }

    public Message noResults(final CharSequence source) {
        return createMessage(Type.ERROR, "no.results", source);
    }

    public Message unknownSource(final CharSequence source) {
        return createMessage(Type.ERROR, "unknown.source", source);
    }

    public Message invalidObjectType(final CharSequence type) {
        return createMessage(Type.ERROR, "invalid.object.type", type);
    }

    public Message invalidAttributeType(final CharSequence type) {
        return createMessage(Type.ERROR, "invalid.attribute.type", type);

    }

    public Message attributeNotSearchable(final CharSequence type) {
        return createMessage(Type.ERROR, "attribute.not.searchable", type);
    }

    public Message noSearchKeySpecified() {
        return createMessage(Type.ERROR, "no.search.key.specified");
    }

    public Message inputTooLong() {
        return createMessage(Type.ERROR, "input.too.long");
    }

    public Message invalidCombinationOfFlags(final CharSequence flag, final CharSequence otherFlag) {
        return createMessage(Type.ERROR, "invalid.combination.of.flags", flag, otherFlag);
    }

    public Message invalidMultipleFlags(final CharSequence flag) {
        return createMessage(Type.ERROR, "invalid.multiple.flags", flag);
    }

    public Message malformedQuery() {
        return createMessage(Type.ERROR, "malformed.query");
    }

    public Message malformedQuery(final String reason) {
        if (StringUtils.isEmpty(reason)) {
            return malformedQuery();
        } else {
            return new QueryMessage(Type.ERROR, String.format("%s\n\n%s", reason, lookupMessage("malformed.query")));
        }
    }

    public Message illegalRange() {
        return createMessage(Type.ERROR, "illegal.range");
    }

    public Message unsupportedQuery() {
        return createMessage(Type.ERROR, "unsupported.query");
    }

    public Message invalidSearchKey() {
        return createMessage(Type.ERROR, "invalid.search.key");
    }

    public Message unsupportedVersionObjectType() {
        return createMessage(Type.ERROR, "unsupported.version.object.type");
    }

    public Message versionOutOfRange(final int max) {
        return createMessage(Type.ERROR, "version.out.of.range", max);
    }

    public Message accessDeniedPermanently(final InetAddress remoteAddress) {
        return createMessage(Type.ERROR, "access.denied.permanently", remoteAddress.getHostAddress());
    }

    public Message accessDeniedTemporarily(final InetAddress remoteAddress) {
        return createMessage(Type.ERROR, "access.denied.temporarily", remoteAddress.getHostAddress());
    }

    public Message notAllowedToProxy() {
        return createMessage(Type.ERROR, "not.allowed.to.proxy");
    }

    public Message timeout() {
        return createMessage(Type.ERROR, "timeout");
    }

    public Message connectionsExceeded(final int connectionLimit) {
        return createMessage(Type.ERROR, "connections.exceeded", connectionLimit);
    }

    public Message duplicateIpFlagsPassed() {
        return createMessage(Type.ERROR, "duplicate.ip.flags.passed");
    }

    public Message uselessIpFlagPassed() {
        return createMessage(Type.WARNING, "useless.ip.flag.passed");
    }

    public Message tagInfoStart(final CharSequence pkey) {
        return createMessage(Type.INFO, "tag.info.start", pkey);
    }

    public Message tagInfo(final CharSequence tagType, final CharSequence tagValue) {
        if (tagValue != null && tagValue.length() > 0) {
            return new QueryMessage(Type.INFO, "%s # %s", tagType, tagValue);

        } else {
            return new QueryMessage(Type.INFO, tagType.toString());
        }
    }

    public Message unreferencedTagInfo(final CharSequence pkey, final CharSequence value) {
        return createMessage(Type.INFO, "unreferenced.tag.info", pkey, value);
    }

    public Message filterTagNote(final Set<? extends CharSequence> includeArgs, final Set<? extends CharSequence> excludeArgs) {
        final StringBuilder message = new StringBuilder(lookupMessage("tag.filtering.enabled"));

        if (!includeArgs.isEmpty()) {
            message.append("      ").append(lookupMessage("only.showing.objects.with.tags", JOINER.join(includeArgs)));
            if (!excludeArgs.isEmpty()) {
                message.append('\n');
            }
        }

        if (!excludeArgs.isEmpty()) {
            message.append("      ").append(lookupMessage("only.showing.objects.without.tags", JOINER.join(excludeArgs)));
        }

        return new QueryMessage(Type.INFO, message.toString());
    }

    public Message invalidSyntax(final CharSequence objectKey) {
        return createMessage(Type.INFO, "invalid.syntax", objectKey);
    }

    public Message validSyntax(final CharSequence objectKey) {
        return createMessage(Type.ERROR, "valid.syntax", objectKey);
    }

    public Message inverseSearchNotAllowed() {
        return createMessage(Type.ERROR, "inverse.search.not.allowed");
    }

    //

    private Message createMessage(final Type type, final String code, final Object ... args) {
        return new QueryMessage(type, lookupMessage(code, args));
    }

    private String lookupMessage(final String code, final Object ... args) {
        try {
            return messageSource.getMessage(code, args, Locale.getDefault());
        } catch (NoSuchMessageException e) {
            LOGGER.error("No such message: " + code, e);
            throw new IllegalStateException(e);
        }
    }
}
