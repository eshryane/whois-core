package net.ripe.db.whois.api.rest;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import net.ripe.db.whois.api.AbstractIntegrationTest;
import net.ripe.db.whois.api.RestTest;
import net.ripe.db.whois.api.rest.domain.ErrorMessage;
import net.ripe.db.whois.api.rest.domain.WhoisResources;
import net.ripe.db.whois.api.rest.mapper.FormattedClientAttributeMapper;
import net.ripe.db.whois.api.rest.mapper.WhoisObjectMapper;
import net.ripe.db.whois.common.EndToEndTest;
import net.ripe.db.whois.common.profiles.WhoisProfile;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.RpslObjectBuilder;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import net.ripe.db.whois.update.support.TestUpdateLog;
import org.joda.time.LocalDateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ActiveProfiles;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import java.text.MessageFormat;
import java.util.List;

import static net.ripe.db.whois.common.rpsl.RpslObjectFilter.buildGenericObject;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

// TODO: [AH] switch this to IntegrationTest once we got the crowd server dummy instead of the real thing in testlab/prepdev
@ActiveProfiles(profiles = WhoisProfile.ENDTOEND, inheritProfiles = false)
@Category(EndToEndTest.class)
public class WhoisRestServiceEndToEndTest extends AbstractIntegrationTest {

    // accounts used for testing on serval.testlab
    public static final String USER1 = "db_e2e_1@ripe.net";
    public static final String PASSWORD1 = "pw_e2e_1";
    public static final String USER2 = "db_e2e_2@ripe.net";
    public static final String PASSWORD2 = "pw_e2e_2";
    public static final String INACTIVE_USER = "db_e2e_3@ripe.net";
    public static final String PASSWORD3 = "pw_e2e_3";

    private static ImmutableMap<String, RpslObject> baseFixtures = ImmutableMap.<String, RpslObject>builder()
            .put("OWNER-MNT", RpslObject.parse("" +
                    "mntner:      OWNER-MNT\n" +
                    "descr:       Owner Maintainer\n" +
                    "admin-c:     TP1-TEST\n" +
                    "upd-to:      noreply@ripe.net\n" +
                    "auth:        MD5-PW $1$fyALLXZB$V5Cht4.DAIM3vi64EpC0w/  #owner\n" +
                    "mnt-by:      OWNER-MNT\n" +
                    "referral-by: OWNER-MNT\n" +
                    "changed:     dbtest@ripe.net 20120101\n" +
                    "source:      TEST"))

            .put("RIPE-NCC-HM-MNT", RpslObject.parse("" +
                    "mntner:      RIPE-NCC-HM-MNT\n" +
                    "descr:       hostmaster MNTNER\n" +
                    "admin-c:     TP1-TEST\n" +
                    "upd-to:      updto_hm@ripe.net\n" +
                    "mnt-nfy:     mntnfy_hm@ripe.net\n" +
                    "notify:      notify_hm@ripe.net\n" +
                    "auth:        MD5-PW $1$mV2gSZtj$1oVwjZr0ecFZQHsNbw2Ss.  #hm\n" +
                    "mnt-by:      RIPE-NCC-HM-MNT\n" +
                    "referral-by: RIPE-NCC-HM-MNT\n" +
                    "changed:     dbtest@ripe.net\n" +
                    "source:      TEST"))

            .put("END-USER-MNT", RpslObject.parse("" +
                    "mntner:      END-USER-MNT\n" +
                    "descr:       used for lir\n" +
                    "admin-c:     TP1-TEST\n" +
                    "upd-to:      updto_lir@ripe.net\n" +
                    "auth:        MD5-PW $1$4qnKkEY3$9NduUoRMNiBbAX9QEDMkh1  #end\n" +
                    "mnt-by:      END-USER-MNT\n" +
                    "referral-by: END-USER-MNT\n" +
                    "changed:     dbtest@ripe.net 20120101\n" +
                    "source:      TEST"))

            .put("TP1-TEST", RpslObject.parse("" +
                    "person:    Test Person\n" +
                    "address:   Singel 258\n" +
                    "phone:     +31 6 12345678\n" +
                    "nic-hdl:   TP1-TEST\n" +
                    "mnt-by:    OWNER-MNT\n" +
                    "changed:   dbtest@ripe.net 20120101\n" +
                    "source:    TEST\n"))

            .put("TR1-TEST", RpslObject.parse("" +
                    "role:      Test Role\n" +
                    "address:   Singel 258\n" +
                    "phone:     +31 6 12345678\n" +
                    "nic-hdl:   TR1-TEST\n" +
                    "admin-c:   TR1-TEST\n" +
                    "abuse-mailbox: abuse@test.net\n" +
                    "mnt-by:    OWNER-MNT\n" +
                    "changed:   dbtest@ripe.net 20120101\n" +
                    "source:    TEST\n"))

            .put("ORG-LIR1-TEST", RpslObject.parse("" +
                    "organisation:    ORG-LIR1-TEST\n" +
                    "org-type:        LIR\n" +
                    "org-name:        Local Internet Registry\n" +
                    "address:         RIPE NCC\n" +
                    "e-mail:          dbtest@ripe.net\n" +
                    "ref-nfy:         dbtest-org@ripe.net\n" +
                    "mnt-ref:         OWNER-MNT\n" +
                    "mnt-by:          OWNER-MNT\n" +
                    "changed: denis@ripe.net 20121016\n" +
                    "source:  TEST\n"))

            .build();

    // TODO: [AH] find an elegant way to run all tests twice, with XML/JSON requests
    // TODO: [AH] XML fails on newline difference
    private final String mediaType = MediaType.APPLICATION_XML;

    @Autowired
    WhoisObjectMapper whoisObjectMapper;

    @Autowired TestUpdateLog updateLog;
    @Value("${dir.update.audit.log}") String auditLog;

    @Before
    public void setup() {
        databaseHelper.addObjects(baseFixtures.values());
        testDateTimeProvider.setTime(LocalDateTime.parse("2001-02-06T17:00:00"));
    }

    @Test
    public void create_inetnum_with_parent_without_status_to_check_error_message_beginning_with_percent_is_handled_correctly() {
        databaseHelper.addObjects(
                new RpslObjectBuilder(makeInetnum("10.0.0.0 - 10.255.255.255")).removeAttributeType(AttributeTypes.STATUS).get()
        );

        final RpslObject assignment = makeInetnum("10.0.0.0 - 10.0.255.255");

        try {
            RestTest.target(getPort(), "whois/test/inetnum")
                    .request(mediaType)
                    .post(Entity.entity(whoisObjectMapper.mapRpslObjects(FormattedClientAttributeMapper.class, assignment), mediaType), WhoisResources.class);
            fail();
        } catch (NotAuthorizedException expected) {
            final WhoisResources whoisResources = expected.getResponse().readEntity(WhoisResources.class);
            final ErrorMessage errorMessage = Lists.reverse(whoisResources.getErrorMessages()).get(0);
            assertThat(errorMessage.getText(), is("%s %s does not have \"status:\""));
            assertThat(errorMessage.toString(), is("Parent 10.0.0.0 - 10.255.255.255 does not have \"status:\""));
        }
    }

    // helper methods

    private RpslObject makeMntner(final String pkey, final String... attributes) {
        return buildGenericObject(MessageFormat.format("" +
                "mntner:      {0}-MNT\n" +
                "descr:       used for lir\n" +
                "admin-c:     TP1-TEST\n" +
                "upd-to:      updto_{0}@ripe.net\n" +
                "mnt-nfy:     mntnfy_{0}@ripe.net\n" +
                "notify:      notify_{0}@ripe.net\n" +
                "mnt-by:      {0}-MNT\n" +
                "referral-by: {0}-MNT\n" +
                "changed:     dbtest@ripe.net\n" +
                "source:      TEST", pkey), attributes);
    }

    private RpslObject makeInetnum(final String pkey, final String... attributes) {
        return buildGenericObject(MessageFormat.format("" +
                "inetnum:      {0}\n" +
                "netname:      TEST-NET-NAME\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "org:          ORG-LIR1-TEST\n" +
                "admin-c:      TP1-TEST\n" +
                "tech-c:       TP1-TEST\n" +
                "mnt-by:       RIPE-NCC-HM-MNT\n" +
                "status:       ALLOCATED PA\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:    TEST\n", pkey), attributes);
    }

    private void assertUnauthorizedErrorMessage(final NotAuthorizedException exception, final String... args) {
        final WhoisResources whoisResources = exception.getResponse().readEntity(WhoisResources.class);
        final List<ErrorMessage> errorMessages = whoisResources.getErrorMessages();
        assertThat(errorMessages.size(), is(1));
        assertThat(errorMessages.get(0).getText(), is("Authorisation for [%s] %s failed\n" +
                "using \"%s:\"\n" +
                "not authenticated by: %s"));
        assertThat(errorMessages.get(0).getArgs().size(), is(args.length));
        for (int i = 0; i < args.length; i++) {
            assertThat(errorMessages.get(0).getArgs().get(i).getValue(), is(args[i]));
        }
    }

    private void reportAndThrowUnknownError(final ClientErrorException e) {
        System.err.println(e.getResponse().getStatus());
        System.err.println(e.getResponse().readEntity(String.class));
        throw e;
    }
}
