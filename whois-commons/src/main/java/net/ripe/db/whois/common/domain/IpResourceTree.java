package net.ripe.db.whois.common.domain;

import net.ripe.db.whois.common.collect.CollectionHelper;
import net.ripe.db.whois.common.etree.IntervalMap;
import net.ripe.db.whois.common.etree.NestedIntervalMap;
import net.ripe.db.whois.common.ip.IpInterval;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;

import java.util.List;

public class IpResourceTree<V> {
    private final IntervalMap<IpInterval<?>, V> ipv4Tree;
    private final IntervalMap<IpInterval<?>, V> ipv6Tree;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public IpResourceTree() {
        this.ipv4Tree = new NestedIntervalMap();
        this.ipv6Tree = new NestedIntervalMap();
    }

    public void add(IpInterval<?> ipInterval, V value) {
        getTree(ipInterval).put(ipInterval, value);
    }

    public V getValue(IpInterval<?> ipInterval) {
        List<V> list = getTree(ipInterval).findExactOrFirstLessSpecific(ipInterval);
        return CollectionHelper.uniqueResult(list);
    }

    private IntervalMap<IpInterval<?>, V> getTree(IpInterval<?> ipInterval) {
        AttributeType type = ipInterval.getAttributeType();

        if (type.equals(AttributeTypes.INETNUM)) {
            return ipv4Tree;
        } else if (type.equals(AttributeTypes.INET6NUM)) {
            return ipv6Tree;
        }
        throw new IllegalArgumentException("Unsupported IP interval object type: " + ipInterval.getAttributeType());
    }
}
