package net.ripe.db.whois.common.rpsl.transform;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.RpslObjectBuilder;
import net.ripe.db.whois.common.rpsl.RpslObjectFilter;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;

import javax.annotation.concurrent.ThreadSafe;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;



@ThreadSafe
public class FilterEmailFunction implements FilterFunction {
    private final Set<AttributeType> filterAttributes = new HashSet<AttributeType>(Lists.newArrayList(
            AttributeTypes.NOTIFY,
            AttributeTypes.CHANGED,
            AttributeTypes.REF_NFY,
            AttributeTypes.MNT_NFY,
            AttributeTypes.UPD_TO,
            AttributeTypes.E_MAIL
    ));

    @Override @NotNull
    public RpslObject apply(RpslObject rpslObject) {
        RpslObjectBuilder builder = new RpslObjectBuilder(rpslObject).removeAttributeTypes(filterAttributes);
        return rpslObject.size() == builder.size() ? rpslObject : RpslObjectFilter.setFiltered(builder).get();
    }
}
