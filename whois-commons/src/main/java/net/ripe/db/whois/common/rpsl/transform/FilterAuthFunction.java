package net.ripe.db.whois.common.rpsl.transform;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.PasswordHelper;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.RpslObjectBuilder;
import net.ripe.db.whois.common.rpsl.RpslObjectFilter;
import org.springframework.util.CollectionUtils;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
password and cookie parameters are used in rest api lookup ONLY, so the port43 netty worker pool is not affected by any SSO
server timeouts or network hiccups. Jetty could suffer from that, though - AH
 */
@ThreadSafe
public class FilterAuthFunction implements FilterFunction {
    public static final Splitter SPACE_SPLITTER = Splitter.on(' ');
    public static final String FILTERED_APPENDIX = " # Filtered";

    private List<String> passwords = null;
    private RpslObjectDao rpslObjectDao = null;

    public FilterAuthFunction(final List<String> passwords,
                              final RpslObjectDao rpslObjectDao) {
        this.passwords = passwords;
        this.rpslObjectDao = rpslObjectDao;
    }

    public FilterAuthFunction() {
    }

    @Override
    public RpslObject apply(final RpslObject rpslObject) {
        final List<RpslAttribute> authAttributes = rpslObject.findAttributes(AttributeType.AUTH);
        if (authAttributes.isEmpty()) {
            return rpslObject;
        }

        final Map<RpslAttribute, RpslAttribute> replace = Maps.newHashMap();
        final boolean authenticated = isMntnerAuthenticated(rpslObject);

        for (final RpslAttribute authAttribute : authAttributes) {
            final Iterator<String> authIterator = SPACE_SPLITTER.split(authAttribute.getCleanValue()).iterator();
            final String passwordType = authIterator.next().toUpperCase();

            if (!authenticated) {
                if (passwordType.endsWith("-PW")) {     // history table has CRYPT-PW, dummify that too!
                    replace.put(authAttribute, new RpslAttribute(AttributeType.AUTH, passwordType + FILTERED_APPENDIX));
                }
            }
        }

        if (replace.isEmpty()) {
            return rpslObject;
        } else {
            if (!authenticated) {
                RpslObjectFilter.addFilteredSourceReplacement(rpslObject, replace);
            }
            return new RpslObjectBuilder(rpslObject).replaceAttributes(replace).get();
        }
    }

    private boolean isMntnerAuthenticated(final RpslObject rpslObject) {
        if (CollectionUtils.isEmpty(passwords)) {
            return false;
        }

        final List<RpslAttribute> extendedAuthAttributes = Lists.newArrayList(rpslObject.findAttributes(AttributeType.AUTH));
        extendedAuthAttributes.addAll(getMntByAuthAttributes(rpslObject));

        return passwordAuthentication(extendedAuthAttributes);
    }

    private Set<RpslAttribute> getMntByAuthAttributes(final RpslObject rpslObject) {
        final Set<CIString> maintainers = rpslObject.getValuesForAttribute(AttributeType.MNT_BY);
        maintainers.remove(rpslObject.getKey());

        if (maintainers.isEmpty()) {
            return Collections.emptySet();
        }

        final Set<RpslAttribute> auths = Sets.newHashSet();
        final List<RpslObject> mntByMntners = rpslObjectDao.getByKeys(ObjectType.MNTNER, maintainers);

        for (RpslObject mntner : mntByMntners) {
            auths.addAll(mntner.findAttributes(AttributeType.AUTH));
        }

        return auths;
    }

    private boolean passwordAuthentication(final List<RpslAttribute> authAttributes) {
        if (CollectionUtils.isEmpty(passwords)) {
            return false;
        }

        for (RpslAttribute authAttribute : authAttributes) {
            if (PasswordHelper.authenticateMd5Passwords(authAttribute.getCleanValue().toString(), passwords)) {
                return true;
            }
        }
        return false;
    }
}
