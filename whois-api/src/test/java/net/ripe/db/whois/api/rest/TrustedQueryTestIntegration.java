package net.ripe.db.whois.api.rest;

import net.ripe.db.whois.api.AbstractIntegrationTest;
import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.domain.IpRanges;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.junit.Before;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;

@Category(IntegrationTest.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class TrustedQueryTestIntegration extends AbstractIntegrationTest {

    @Autowired IpRanges ipRanges;

    @Before
    public void setup() {
        databaseHelper.addObject(
                "person:    Test Person\n" +
                "nic-hdl:   TP1-TEST\n" +
                "source:    TEST");
        databaseHelper.addObject(
                "mntner:    OWNER-MNT\n" +
                "source:    TEST");
        databaseHelper.addObject(
                "aut-num:   AS102\n" +
                "source:    TEST\n");
        databaseHelper.addObject(RpslObject.parse("" +
                "organisation: ORG-RIPE\n" +
                "org-name:     Test Organisation Ltd\n" +
                "org-type:     LIR\n" +
                "descr:        test org\n" +
                "address:      street 5\n" +
                "e-mail:       org1@test.com\n" +
                "mnt-ref:      OWNER-MNT\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20120505\n" +
                "source:       TEST\n" +
                ""));
        databaseHelper.addObject(RpslObject.parse("" +
                "inetnum:       194.0.0.0 - 194.255.255.255\n" +
                "org:           ORG-RIPE\n" +
                "netname:       TEST-NET\n" +
                "descr:         description\n" +
                "country:       NL\n" +
                "admin-c:       TP1-TEST\n" +
                "tech-c:        TP1-TEST\n" +
                "status:        ALLOCATED PA\n" +
                "mnt-by:        OWNER-MNT\n" +
                "mnt-lower:     OWNER-MNT\n" +
                "changed:       ripe@test.net 20120505\n" +
                "source:        TEST\n"));
    }
}
