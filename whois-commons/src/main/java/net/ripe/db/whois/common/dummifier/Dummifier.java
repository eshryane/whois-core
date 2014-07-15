package net.ripe.db.whois.common.dummifier;

import net.ripe.db.whois.common.rpsl.RpslObject;

public interface Dummifier {
    RpslObject dummify(int version, RpslObject rpslObject);

    boolean isAllowed(int version, RpslObject rpslObject);
}
