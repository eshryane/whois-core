package net.ripe.db.whois.common.rpsl;

import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.zip.GZIPInputStream;

// TODO: [AH] make this rely on downloader (or make it more visible if those files are missing and no tests are actually run)
@Category(IntegrationTest.class)
public class AttributeParserTestIntegration {

    private static final Logger LOGGER = LoggerFactory.getLogger(AttributeParserTestIntegration.class);

    @Test
    public void parseAutnumAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.aut-num.gz",
                new AttributeType[]{
                        AttributeTypes.EXPORT,
                        AttributeTypes.IMPORT,
                        AttributeTypes.DEFAULT,
                        AttributeTypes.MP_EXPORT,
                        AttributeTypes.MP_IMPORT,
                        AttributeTypes.MP_DEFAULT,
                        AttributeTypes.MNT_ROUTES
                }
        );
    }

    @Test
    public void parseInetRtrAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.inet-rtr.gz",
                new AttributeType[]{
                        AttributeTypes.ALIAS,
                        AttributeTypes.IFADDR,
                        AttributeTypes.INTERFACE,
                        AttributeTypes.PEER,
                        AttributeTypes.MP_PEER
                }
        );
    }

    @Test
    public void parseAsSetAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.as-set.gz",
                new AttributeType[]{
                        AttributeTypes.MEMBERS
                }
        );
    }

    @Test
    public void parseRouteSetAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.route-set.gz",
                new AttributeType[]{
                        AttributeTypes.MEMBERS,
                        AttributeTypes.MP_MEMBERS
                }
        );
    }

    @Test
    public void parseRtrSetAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.rtr-set.gz",
                new AttributeType[]{
                        AttributeTypes.MEMBERS,
                        AttributeTypes.MP_MEMBERS
                }
        );
    }

    @Test
    public void parseFilterSetAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.filter-set.gz",
                new AttributeType[]{
                        AttributeTypes.FILTER,
                        AttributeTypes.MP_FILTER
                }
        );
    }

    @Test
    public void parsePeeringSetAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.peering-set.gz",
                new AttributeType[]{
                        AttributeTypes.PEERING,
                        AttributeTypes.MP_PEERING
                }
        );
    }

    @Test
    public void parseRouteAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.route.gz",
                new AttributeType[]{
                        AttributeTypes.INJECT,
                        AttributeTypes.AGGR_MTD,
                        AttributeTypes.AGGR_BNDRY,
                        AttributeTypes.COMPONENTS,
                        AttributeTypes.EXPORT_COMPS,
                        AttributeTypes.MNT_ROUTES
                }
        );
    }

    @Test
    public void parseRoute6Attributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.route6.gz",
                new AttributeType[]{
                        AttributeTypes.INJECT,
                        AttributeTypes.AGGR_MTD,
                        AttributeTypes.AGGR_BNDRY,
                        AttributeTypes.COMPONENTS,
                        AttributeTypes.EXPORT_COMPS,
                        AttributeTypes.MNT_ROUTES
                }
        );
    }

    @Test
    public void parseInetnumAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.inetnum.gz",
                new AttributeType[]{
                        AttributeTypes.MNT_ROUTES
                }
        );
    }

    @Test
    public void parseInet6numAttributes() throws Exception {
        parseAttributes("/export/opt/ripe.db.inet6num.gz",
                new AttributeType[]{
                        AttributeTypes.MNT_ROUTES
                }
        );
    }

    private void parseAttributes(final String file, final AttributeType[] types) throws IOException {
        try {
            InputStream inputStream = new GZIPInputStream((new FileInputStream(file)));
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

            StringBuilder builder = new StringBuilder();

            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.length() == 0) {
                        final String rpslString = builder.toString().trim();
                        builder.setLength(0);

                        if (rpslString.length() > 0) {
                            RpslObject rpslObject;
                            try {
                                rpslObject = RpslObject.parse(rpslString);
                            } catch (IllegalArgumentException e) {
                                LOGGER.info("RpslObject {} could not be parsed", rpslString);
                                continue;
                            }

                            parseAttributes(rpslObject, types);
                        }
                    } else {
                        if (!line.startsWith("#")) {
                            builder.append(line);
                        }
                        builder.append('\n');
                    }
                }
            } finally {
                reader.close();
            }
        } catch (FileNotFoundException e) {
            // ignore
        }
    }

    private void parseAttributes(final RpslObject rpslObject, final AttributeType[] types) {
        for (AttributeType type : types) {
            for (RpslAttribute attribute : rpslObject.findAttributes(type)) {
                for (CIString cleanValue : attribute.getCleanValues()) {
                    if (!type.isValidValue(rpslObject.getType(), cleanValue)) {
                        LOGGER.info("FAIL: type={}.{} value={}", rpslObject.getType().getName(), type, cleanValue);
                    }
                }
            }
        }
    }
}
