package net.ripe.db.whois.common.query.planner;

import com.google.common.base.Function;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslAttributeFilter;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

class ToShorthandFunction implements Function<ResponseObject, ResponseObject> {
    @Override
    public ResponseObject apply(final @Nullable ResponseObject input) {
        if (!(input instanceof RpslObject)) {
            return input;
        }

        final RpslObject rpslObject = (RpslObject) input;
        final List<RpslAttribute> attributes = rpslObject.getAttributes();

        final List<RpslAttribute> newAttributes = new ArrayList<>(attributes.size());
        for (RpslAttribute attribute : attributes) {
            final AttributeType type = attribute.getType();
            final String key = type != null ? "*" + type.getFlag() : attribute.getKey();

            newAttributes.add(new RpslAttribute(key, RpslAttributeFilter.getValueForShortHand(attribute.getValue())));
        }

        return new RpslObject(rpslObject, newAttributes);
    }
}
