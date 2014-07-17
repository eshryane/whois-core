package net.ripe.db.whois.common.dao.jdbc.index;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import net.ripe.db.whois.common.rpsl.impl.Mntner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static net.ripe.db.whois.common.domain.CIString.ciString;

class IndexWithMaintainer extends IndexWithValue {
    @Autowired
    private IObjectTypeFactory objectTypeFactory;

    private static final CIString ANY = ciString("ANY");

    public IndexWithMaintainer(final AttributeType attributeType, final String lookupTableName, final String lookupColumnName) {
        super(attributeType, lookupTableName, lookupColumnName);
    }

    @Override
    public List<RpslObjectInfo> findInIndex(final JdbcTemplate jdbcTemplate, final String value) {
        if (ANY.equals(value)) {
            return Lists.newArrayList(new RpslObjectInfo(0, objectTypeFactory.get(Mntner.class), ANY));
        }

        return super.findInIndex(jdbcTemplate, value);
    }
}
