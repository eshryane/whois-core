package net.ripe.db.whois.common.dao;

import net.ripe.db.whois.common.collect.ProxyLoader;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Identifiable;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;

import javax.annotation.Nullable;
import java.util.Collection;
import java.util.List;
import java.util.Set;

// these should return Collection<> instead of List<> to allow for greater flexibility in implementation
public interface RpslObjectDao extends ProxyLoader<Identifiable, RpslObject> {
    RpslObject getById(int objectId);

    RpslObject getByKey(IObjectType type, CIString key);

    RpslObject getByKey(IObjectType type, String searchKey);

    @Nullable
    RpslObject getByKeyOrNull(IObjectType type, CIString key);

    @Nullable
    RpslObject getByKeyOrNull(IObjectType type, String searchKey);

    List<RpslObject> getByKeys(IObjectType type, Collection<CIString> searchKeys);

    RpslObject findAsBlock(long begin, long end);

    List<RpslObject> findAsBlockIntersections(long begin, long end);

    RpslObjectInfo findByKey(IObjectType type, String searchKey);

    RpslObjectInfo findByKey(IObjectType type, CIString searchKey);

    @Nullable
    RpslObjectInfo findByKeyOrNull(IObjectType type, String searchKey);

    @Nullable
    RpslObjectInfo findByKeyOrNull(IObjectType type, CIString searchKey);

    List<RpslObjectInfo> findByAttribute(AttributeType attributeType, String attributeValue);

    List<RpslObjectInfo> findMemberOfByObjectTypeWithoutMbrsByRef(IObjectType objectType, String attributeValue);

    Collection<RpslObjectInfo> relatedTo(RpslObject identifiable, Set<IObjectType> excludeObjectTypes);
}
