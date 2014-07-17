package net.ripe.db.whois.common.dao.jdbc.domain;

import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public final class RpslObjectInfoMapper implements RowMapper<RpslObjectInfo> {
    private static final Logger LOGGER = LoggerFactory.getLogger(RpslObjectInfoMapper.class);

    @Autowired
    private IObjectTypeFactory objectTypeFactory;

    @Override
    public RpslObjectInfo mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        final int objectId = rs.getInt(1);
        final int type = rs.getInt(2);
        final String pkey = rs.getString(3);

        try {
            return new RpslObjectInfo(objectId, objectTypeFactory.get(type), pkey);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Unsupported object with id: {}, type: {}", objectId, type);
            return null;
        }
    }
}
