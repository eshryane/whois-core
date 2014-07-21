package net.ripe.db.whois.common.dao.jdbc.index;

import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import org.apache.commons.lang.Validate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collections;
import java.util.List;

abstract class IndexStrategyAdapter implements IndexStrategy {
    protected final AttributeType attributeType;

    public IndexStrategyAdapter(final AttributeType attributeType) {
        Validate.notNull(attributeType);
        this.attributeType = attributeType;
    }

    @Override
    public final AttributeType getAttributeType() {
        return attributeType;
    }

    @Override
    public final int addToIndex(final JdbcTemplate jdbcTemplate, final RpslObjectInfo objectInfo, final RpslObject object, final CIString value) {
        return addToIndex(jdbcTemplate, objectInfo, object, value.toString());
    }

    @Override
    public int addToIndex(final JdbcTemplate jdbcTemplate, final RpslObjectInfo objectInfo, final RpslObject object, final String value) {
        return 1;
    }

    @Override
    public final List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final CIString value) {
        return findInIndex(jdbcTemplate, value.toString());
    }

    @Override
    public List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final String value) {
        return Collections.emptyList();
    }

    @Override
    public final List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final CIString value, final ObjectType type) {
        return findInIndex(jdbcTemplate, value.toString(), type);
    }

    @Override
    public List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final String value, final ObjectType type) {
        return findInIndex(jdbcTemplate, value);
    }

    @Override
    public List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final RpslObjectInfo value) {
        return Collections.emptyList();
    }

    @Override
    public List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final RpslObjectInfo value, final ObjectType type) {
        return Collections.emptyList();
    }

    @Override
    public void removeFromIndex(final JdbcTemplate jdbcTemplate, final RpslObjectInfo objectInfo) {
    }

    @Override
    public String getLookupTableName() {
        return null;
    }

    @Override
    public void cleanupMissingObjects(final JdbcTemplate jdbcTemplate) {
    }

    @Override
    public String getLookupColumnName() {
        return null;
    }
}
