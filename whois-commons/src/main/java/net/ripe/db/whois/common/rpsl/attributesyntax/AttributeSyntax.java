package net.ripe.db.whois.common.rpsl.attributesyntax;

import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;



// TODO: [AH] queries should NOT match AUTO- versions of keys, we should remove the AUTO- patterns from here
// TODO: [AH] fix capture groups (add '?:' where capture is not needed)
public interface AttributeSyntax extends Documented {
    boolean matches(ObjectType objectType, String value);
}
