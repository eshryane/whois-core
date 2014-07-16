package net.ripe.db.whois.common.query.domain;

import net.ripe.db.whois.common.collect.CollectionHelper;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.domain.Tag;
import net.ripe.db.whois.common.query.QueryMessages;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public final class TagResponseObject implements ResponseObject {
    private final CIString objectKey;
    private final List<Tag> tags;
    private QueryMessages queryMessages;

    public TagResponseObject(final CIString objectKey, final List<Tag> tags, final QueryMessages queryMessages) {
        this.objectKey = objectKey;
        this.tags = tags;
        this.queryMessages = queryMessages;
    }

    public List<Tag> getTags() {
        return tags;
    }

    @Override
    public String toString() {
        if (tags.isEmpty()) return "";

        final StringBuilder builder = new StringBuilder(128);
        builder.append(queryMessages.tagInfoStart(objectKey));

        for (Tag tag : tags) {
            if (tag.getType().equals("unref")) {
                builder.append(queryMessages.unreferencedTagInfo(objectKey, tag.getValue()));
            } else {
                builder.append(queryMessages.tagInfo(tag.getType(), tag.getValue()));
            }
        }

        return builder.toString();
    }

    @Override
    public void writeTo(final OutputStream out) throws IOException {
        out.write(toByteArray());
    }

    @Override
    public byte[] toByteArray() {
        if (tags.isEmpty()) return CollectionHelper.EMPTY_BYTE_ARRAY;

        return toString().getBytes();
    }
}
