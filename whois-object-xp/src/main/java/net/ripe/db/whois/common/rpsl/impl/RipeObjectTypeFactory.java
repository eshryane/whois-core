package net.ripe.db.whois.common.rpsl.impl;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class RipeObjectTypeFactory implements IObjectTypeFactory {

    public static final int DUMMY_OBJECT_TYPE_ID = 100;

    protected final Map<String, IObjectType> TYPE_NAMES;
    protected final Set<IObjectType> SET_OBJECTS;
    protected final Set<IObjectType> RESOURCE_TYPES;
    protected final Map<Integer, IObjectType> BY_TYPE_ID;
    protected final Map<Class<? extends IObjectType>, IObjectType> TYPE_CLASSES;

    @Autowired
    public RipeObjectTypeFactory(final List<IObjectType> objectTypes) {
        Map<String, IObjectType> typeNames = new HashMap<>(objectTypes.size() * 2, 1);
        Set<IObjectType> setObjects = Sets.newHashSet();
        Set<IObjectType> resourceTypes = Sets.newHashSet();
        Map<Integer, IObjectType> byTypeId = Maps.newHashMap();
        Map<Class<? extends IObjectType>, IObjectType> typeClasses = Maps.newHashMap();

        for (final IObjectType type : objectTypes) {
            insertInTypeClasses(type, typeClasses);
            insertInTypeNames(type, typeNames, setObjects, resourceTypes);
            insertInByTypeIds(type, byTypeId);
        }

        TYPE_NAMES = Collections.unmodifiableMap(typeNames);
        SET_OBJECTS = Collections.unmodifiableSet(setObjects);
        RESOURCE_TYPES = Collections.unmodifiableSet(resourceTypes);
        BY_TYPE_ID = Collections.unmodifiableMap(byTypeId);
        TYPE_CLASSES = Collections.unmodifiableMap(typeClasses);
    }

    private void insertInTypeClasses(IObjectType type, Map<Class<? extends IObjectType>, IObjectType> typeClasses) {
        Class typeClass = type.getClass();
        IObjectType existingType = typeClasses.get(typeClass);
        if (existingType != null) {
            throw new RuntimeException("The type " + typeClass + " already exists.");
        }
        typeClasses.put(typeClass, type);
    }

    private void insertInTypeNames(IObjectType type, Map<String, IObjectType> typeNames, Set<IObjectType> setObjects, Set<IObjectType> resourceTypes) {
        typeNames.put(type.getName(), type);
        typeNames.put(type.getShortName(), type);

        if (type.isSet()) {
            setObjects.add(type);
        }

        if (type.isResource()) {
            resourceTypes.add(type);
        }
    }

    private void insertInByTypeIds(IObjectType type, Map<Integer, IObjectType> byTypeId) {
        int typeId = type.getId();
        IObjectType existingType = byTypeId.get(typeId);
        if (existingType != null) {
            throw new RuntimeException("A type of id " + typeId + " already exists : " + existingType.getName());
        }
        byTypeId.put(type.getId(), type);
    }

    @Override
    public IObjectType get(final String typeName) throws IllegalArgumentException {
        final IObjectType ret = getByNameOrNull(typeName);
        if (ret == null) {
            throw new IllegalArgumentException("Object type " + typeName + " not found");
        }
        return ret;
    }

    private IObjectType getByNameOrNull(final String name) {
        String nameOrNull = name;
        if (nameOrNull.length() == 3 && nameOrNull.charAt(0) == '*') {
            nameOrNull = nameOrNull.substring(1);
        }
        return TYPE_NAMES.get(nameOrNull);
    }

    public Set<IObjectType> getSets() {
        return SET_OBJECTS;
    }

    @Override
    public IObjectType get(final int typeId) throws IllegalArgumentException {
        final IObjectType objectType = BY_TYPE_ID.get(typeId);
        if (objectType == null) {
            throw new IllegalArgumentException("Object type with objectTypeId " + typeId + " not found");
        }

        return objectType;
    }

    @Override
    public IObjectType get(Class<? extends IObjectType> clazz) {
        return TYPE_CLASSES.get(clazz);
    }

    @Override
    public Collection<IObjectType> values() {
        return Collections.unmodifiableCollection(TYPE_CLASSES.values());
    }

    @Override
    public Set<IObjectType> getResources() {
        return RESOURCE_TYPES;
    }
}
