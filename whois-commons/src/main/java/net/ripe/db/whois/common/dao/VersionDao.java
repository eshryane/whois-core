package net.ripe.db.whois.common.dao;

import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;

import javax.annotation.Nullable;
import java.util.Set;

public interface VersionDao {
    RpslObject getRpslObject(VersionInfo info);

    @Nullable
    VersionLookupResult findByKey(IObjectType type, String searchKey);

    Set<IObjectType> getObjectType(String searchKey);
}
