package net.ripe.db.whois.common.grs;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.etree.IntervalMap;
import net.ripe.db.whois.common.etree.NestedIntervalMap;
import net.ripe.db.whois.common.ip.Ipv4Resource;
import net.ripe.db.whois.common.ip.Ipv6Resource;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.impl.AutNum;
import net.ripe.db.whois.common.rpsl.impl.Inet6Num;
import net.ripe.db.whois.common.rpsl.impl.InetNum;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

@Immutable
public class AuthoritativeResource {
    @Autowired
    private IObjectTypeFactory objectTypeFactory;

    private final Set<CIString> autNums;
    private final IntervalMap<Ipv4Resource, Ipv4Resource> inetRanges;
    private final int nrInetRanges;
    private final IntervalMap<Ipv6Resource, Ipv6Resource> inet6Ranges;
    private final int nrInet6Ranges;

    public static AuthoritativeResource loadFromFile(final Logger logger, final String name, final Path path) {
        try (final Scanner scanner = new Scanner(path)) {
            return loadFromScanner(logger, name, scanner);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static AuthoritativeResource unknown() {
        return new AuthoritativeResource(Collections.<CIString>emptySet(), new NestedIntervalMap<Ipv4Resource, Ipv4Resource>(), new NestedIntervalMap<Ipv6Resource, Ipv6Resource>());
    }

    public static AuthoritativeResource loadFromScanner(final Logger logger, final String name, final Scanner scanner) {
        return new AuthoritativeResourceLoader(logger, name, scanner).load();
    }

    public AuthoritativeResource(final Set<CIString> autNums, final IntervalMap<Ipv4Resource, Ipv4Resource> inetRanges, final IntervalMap<Ipv6Resource, Ipv6Resource> inet6Ranges) {
        this.autNums = autNums;
        this.inetRanges = inetRanges;
        this.inet6Ranges = inet6Ranges;
        this.nrInetRanges = inetRanges.findExactAndAllMoreSpecific(Ipv4Resource.MAX_RANGE).size();
        this.nrInet6Ranges = inet6Ranges.findExactAndAllMoreSpecific(Ipv6Resource.MAX_RANGE).size();
    }

    public int getNrAutNums() {
        return autNums.size();
    }

    public int getNrInetnums() {
        return nrInetRanges;
    }

    public int getNrInet6nums() {
        return nrInet6Ranges;
    }

    boolean isEmpty() {
        return getNrAutNums() == 0 && getNrInetnums() == 0 && getNrInet6nums() == 0;
    }

    private Ipv4Resource concatenateIpv4Resources(final List<Ipv4Resource> resources) {
        if (resources.isEmpty()) {
            throw new IllegalArgumentException();
        }

        for (int index = 1; index < resources.size(); index++) {
            if (resources.get(index).begin() != resources.get(index - 1).end() + 1) {
                throw new IllegalArgumentException("found gap");
            }
        }

        return new Ipv4Resource(resources.get(0).begin(), resources.get(resources.size() - 1).end());
    }

    private Ipv6Resource concatenateIpv6Resources(final List<Ipv6Resource> resources) {
        if (resources.isEmpty()) {
            throw new IllegalArgumentException();
        }

        for (int index = 1; index < resources.size(); index++) {
            if (!resources.get(index).begin().equals(resources.get(index - 1).end().add(BigInteger.ONE))) {
                throw new IllegalArgumentException("found gap");
            }
        }

        return new Ipv6Resource(resources.get(0).begin(), resources.get(resources.size() - 1).end());
    }

    // TODO: since authresource is a dumb container of resources, perhaps containsExactly() would be a better name for this
    public boolean isMaintainedByRir(final IObjectType objectType, final CIString pkey) {
        try {
            if (objectType.equals(objectTypeFactory.get(AutNum.class))) {
                return autNums.contains(pkey);
            } else if (objectType.equals(objectTypeFactory.get(InetNum.class))) {
                final Ipv4Resource pkeyResource = Ipv4Resource.parse(pkey);

                if (!inetRanges.findExact(pkeyResource).isEmpty()) {
                    return true;
                }

                List<Ipv4Resource> matches = inetRanges.findFirstMoreSpecific(pkeyResource);
                if (matches.isEmpty()) {
                    return false;
                }

                try {
                    Ipv4Resource concatenatedResource = concatenateIpv4Resources(matches);
                    if (concatenatedResource.compareTo(pkeyResource) == 0) {
                        return true;
                    }
                } catch (IllegalArgumentException ignored) {
                    // empty match or gap in range
                }

                return false;
            } else if (objectType.equals(objectTypeFactory.get(Inet6Num.class))) {
                final Ipv6Resource pkeyResource = Ipv6Resource.parse(pkey);

                if (!inet6Ranges.findExact(pkeyResource).isEmpty()) {
                    return true;
                }

                List<Ipv6Resource> matches = inet6Ranges.findFirstMoreSpecific(pkeyResource);
                if (matches.isEmpty()) {
                    return false;
                }

                try {
                    Ipv6Resource concatenatedResource = concatenateIpv6Resources(matches);
                    if (concatenatedResource.compareTo(pkeyResource) == 0) {
                        return true;
                    }
                } catch (IllegalArgumentException ignored) {
                    // empty match or gap in range
                }

                return false;
            }
            return true;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    // TODO: since authresource is a dumb container of resources, perhaps contains() or encompasses() would be a better name for this
    public boolean isMaintainedInRirSpace(final RpslObject rpslObject) {
        return isMaintainedInRirSpace(rpslObject.getType(), rpslObject.getKey());
    }

    public boolean isMaintainedInRirSpace(final IObjectType objectType, final CIString pkey) {
        try {
            if (objectType.equals(objectTypeFactory.get(AutNum.class))) {
                return autNums.contains(pkey);
            } else if (objectType.equals(objectTypeFactory.get(InetNum.class))) {
                return !inetRanges.findExactOrFirstLessSpecific(Ipv4Resource.parse(pkey)).isEmpty();
            } else if (objectType.equals(objectTypeFactory.get(Inet6Num.class))) {
                return !inet6Ranges.findExactOrFirstLessSpecific(Ipv6Resource.parse(pkey)).isEmpty();
            }

            return true;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    //public Set<ObjectType> getResourceTypes() { return RESOURCE_TYPES; }

    public Set<CIString> getAutNums() {
        return autNums;
    }

    IntervalMap<Ipv4Resource, Ipv4Resource> getInetRanges() {
        return inetRanges;
    }

    IntervalMap<Ipv6Resource, Ipv6Resource> getInet6Ranges() {
        return inet6Ranges;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AuthoritativeResource that = (AuthoritativeResource) o;

        return autNums.equals(that.autNums) && inet6Ranges.equals(that.inet6Ranges) && inetRanges.equals(that.inetRanges);
    }

    @Override
    public int hashCode() {
        int result = (autNums == null ? 0 : autNums.hashCode());
        result = 31 * result + (inetRanges == null ? 0 : inetRanges.hashCode());
        result = 31 * result + (inet6Ranges == null ? 0 : inet6Ranges.hashCode());
        return result;
    }

    public List<String> getResources() {
        return Lists.newArrayList(Iterables.concat(
                Iterables.transform(autNums, new Function<CIString, String>() {
                    @Override
                    public String apply(CIString input) {
                        return input.toString();
                    }
                }),
                Iterables.transform(inetRanges.findExactAndAllMoreSpecific(Ipv4Resource.MAX_RANGE), new Function<Ipv4Resource, String>() {
                    @Override
                    public String apply(Ipv4Resource input) {
                        return input.toRangeString();
                    }
                }),
                Iterables.transform(inet6Ranges.findExactAndAllMoreSpecific(Ipv6Resource.MAX_RANGE), new Function<Ipv6Resource, String>() {
                    @Override
                    public String apply(Ipv6Resource input) {
                        return input.toString();
                    }
                })
        ));
    }
}

