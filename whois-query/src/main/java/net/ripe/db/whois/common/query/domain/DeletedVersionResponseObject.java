package net.ripe.db.whois.common.query.domain;

import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.query.QueryMessages;
import net.ripe.db.whois.common.query.VersionDateTime;
import net.ripe.db.whois.common.rpsl.ObjectType;

import java.io.IOException;
import java.io.OutputStream;

public class DeletedVersionResponseObject implements ResponseObject {
    private final VersionDateTime deletedDate;
    private final ObjectType type;
    private final String key;
    private final QueryMessages queryMessages;

    public DeletedVersionResponseObject(final VersionDateTime deletedDate, final ObjectType type, final String key, final QueryMessages queryMessages) {
        this.deletedDate = deletedDate;
        this.type = type;
        this.key = key;
        this.queryMessages = queryMessages;
    }

    public VersionDateTime getDeletedDate() {
        return deletedDate;
    }

    public ObjectType getType() {
        return type;
    }

    public String getKey() {
        return key;
    }

    @Override
    public void writeTo(final OutputStream out) throws IOException {
        out.write(toByteArray());
    }

    @Override
    public byte[] toByteArray() {
        return queryMessages.versionDeleted(deletedDate.toString()).toString().getBytes();
    }
}
