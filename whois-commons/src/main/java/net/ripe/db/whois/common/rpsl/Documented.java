package net.ripe.db.whois.common.rpsl;

import com.google.common.collect.Maps;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

interface Documented {
    String getDescription(IObjectType objectType);

    class Single implements Documented {
        private final String description;

        public Single(final String description) {
            this.description = description;
        }

        @Override
        public String getDescription(final IObjectType objectType) {
            return description;
        }
    }

    class Multiple implements Documented {
        private final Map<IObjectType, String> descriptionMap = Maps.newHashMap();

        public Multiple(final Map<IObjectType, String> descriptionMap) {
            this.descriptionMap.putAll(descriptionMap);
        }

        @Override
        public String getDescription(final IObjectType objectType) {
            final String description = descriptionMap.get(objectType);
            return description == null ? "" : description;
        }
    }
}
