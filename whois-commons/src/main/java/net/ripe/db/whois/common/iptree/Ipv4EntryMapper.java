package net.ripe.db.whois.common.iptree;

import net.ripe.db.whois.common.ip.Ipv4Resource;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public final class Ipv4EntryMapper implements RowMapper<Ipv4Entry> {

    @Override
    public Ipv4Entry mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new Ipv4Entry(new Ipv4Resource(rs.getLong(1), rs.getLong(2)), rs.getInt(3));
    }
}
