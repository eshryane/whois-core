package net.ripe.db.whois.common.rpsl;

import java.util.Collection;
import java.util.Set;

/**
 * Created by michel on 7/11/14.
 */
public interface IObjectTypeFactory {
    IObjectType get(Class<? extends IObjectType> clazz);
    IObjectType get(String typeName);
    IObjectType get(int typeId);
    Collection<IObjectType> values();
    Set<IObjectType> getSets();
    Set<IObjectType> getResources();
}
