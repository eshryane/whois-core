package net.ripe.db.whois.common.dao.jdbc.index;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import org.apache.commons.lang.Validate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class IndexStrategies {
    private static final Map<AttributeType, IndexStrategy> INDEX_BY_ATTRIBUTE;
    private static final Map<ObjectType, List<IndexStrategy>> INDEXES_REFERING_OBJECT;

    static {
        final IndexStrategy[] indexStrategies = {
                new IndexWithReference(AttributeTypes.ABUSE_C, "abuse_c", "pe_ro_id"),
                new IndexWithValueAndType(AttributeTypes.ABUSE_MAILBOX, "abuse_mailbox", "abuse_mailbox"),
                new Unindexed(AttributeTypes.ADDRESS),
                new IndexWithReference(AttributeTypes.ADMIN_C, "admin_c", "pe_ro_id"),
                new Unindexed(AttributeTypes.AGGR_BNDRY),
                new Unindexed(AttributeTypes.AGGR_MTD),
                new Unindexed(AttributeTypes.ALIAS),
                new Unindexed(AttributeTypes.ASSIGNMENT_SIZE),
                new IndexWithAsBlock(AttributeTypes.AS_BLOCK),
                new Unindexed(AttributeTypes.AS_NAME),
                new IndexWithValue(AttributeTypes.AS_SET, "as_set", "as_set"),
                new IndexWithAuth(AttributeTypes.AUTH, "auth", "auth"),
                new IndexWithReference(AttributeTypes.AUTHOR, "author", "pe_ro_id"),
                new IndexWithValue(AttributeTypes.AUT_NUM, "aut_num", "aut_num"),
                new Unindexed(AttributeTypes.CERTIF),
                new Unindexed(AttributeTypes.CHANGED),
                new Unindexed(AttributeTypes.COMPONENTS),
                new Unindexed(AttributeTypes.COUNTRY),
                new Unindexed(AttributeTypes.DEFAULT),
                new Unindexed(AttributeTypes.DESCR),
                new IndexWithValue(AttributeTypes.DOMAIN, "domain", "domain"),
                new IndexWithValue(AttributeTypes.DS_RDATA, "ds_rdata", "ds_rdata"),
                new Unindexed(AttributeTypes.ENCRYPTION),
                new Unindexed(AttributeTypes.EXPORT),
                new Unindexed(AttributeTypes.EXPORT_VIA),
                new Unindexed(AttributeTypes.EXPORT_COMPS),
                new IndexWithValueAndType(AttributeTypes.E_MAIL, "e_mail", "e_mail"),
                new Unindexed(AttributeTypes.FAX_NO),
                new Unindexed(AttributeTypes.FILTER),
                new IndexWithValue(AttributeTypes.FILTER_SET, "filter_set", "filter_set"),
                new IndexWithValue(AttributeTypes.FINGERPR, "fingerpr", "fingerpr"),
                new IndexWithReference(AttributeTypes.FORM, "form", "form_id"),
                new Unindexed(AttributeTypes.GEOLOC),
                new Unindexed(AttributeTypes.HOLES),
                new IndexWithIfAddr(AttributeTypes.IFADDR),
                new Unindexed(AttributeTypes.IMPORT),
                new Unindexed(AttributeTypes.IMPORT_VIA),
                new IndexWithInet6num(AttributeTypes.INET6NUM),
                new IndexWithInetnum(AttributeTypes.INETNUM),
                new IndexWithValue(AttributeTypes.INET_RTR, "inet_rtr", "inet_rtr"),
                new Unindexed(AttributeTypes.INJECT),
                new Unindexed(AttributeTypes.INTERFACE),
                new IndexWithValue(AttributeTypes.IRT, "irt", "irt"),
                new IndexWithValue(AttributeTypes.IRT_NFY, "irt_nfy", "irt_nfy"),
                new IndexWithValue(AttributeTypes.KEY_CERT, "key_cert", "key_cert"),
                new Unindexed(AttributeTypes.LANGUAGE),
                new IndexWithLocalAs(AttributeTypes.LOCAL_AS),
                new IndexWithReference(AttributeTypes.MBRS_BY_REF, "mbrs_by_ref", "mnt_id"),
                new Unindexed(AttributeTypes.MEMBERS),
                new IndexWithMemberOf(AttributeTypes.MEMBER_OF),
                new Unindexed(AttributeTypes.METHOD),
                new IndexWithMaintainer(AttributeTypes.MNTNER, "mntner", "mntner"),
                new IndexWithReference(AttributeTypes.MNT_BY, "mnt_by", "mnt_id"),
                new IndexWithReference(AttributeTypes.MNT_DOMAINS, "mnt_domains", "mnt_id"),
                new IndexWithReference(AttributeTypes.MNT_IRT, "mnt_irt", "irt_id"),
                new IndexWithReference(AttributeTypes.MNT_LOWER, "mnt_lower", "mnt_id"),
                new IndexWithValue(AttributeTypes.MNT_NFY, "mnt_nfy", "mnt_nfy"),
                new IndexWithReference(AttributeTypes.MNT_REF, "mnt_ref", "mnt_id"),
                new IndexWithMntRoutes(AttributeTypes.MNT_ROUTES),
                new Unindexed(AttributeTypes.MP_DEFAULT),
                new Unindexed(AttributeTypes.MP_EXPORT),
                new Unindexed(AttributeTypes.MP_FILTER),
                new Unindexed(AttributeTypes.MP_IMPORT),
                new Unindexed(AttributeTypes.MP_MEMBERS),
                new Unindexed(AttributeTypes.MP_PEER),
                new Unindexed(AttributeTypes.MP_PEERING),
                new Unindexed(AttributeTypes.NETNAME),   // TODO: [AH] ATM this is handled by JdbcInetnumDao/JdbcInet6numDao as a special case
                new IndexWithValueAndType(AttributeTypes.NIC_HDL, "person_role", "nic_hdl"),
                new IndexWithValueAndType(AttributeTypes.NOTIFY, "notify", "notify"),
                new IndexWithNServer(AttributeTypes.NSERVER, "nserver", "host"),
                new IndexWithReference(AttributeTypes.ORG, "org", "org_id"),
                new Unindexed(AttributeTypes.ORG_TYPE),
                new IndexWithValue(AttributeTypes.ORGANISATION, "organisation", "organisation"),
                new IndexWithName(AttributeTypes.ORG_NAME, "org_name"),
                new IndexWithOrigin(AttributeTypes.ORIGIN),
                new Unindexed(AttributeTypes.OWNER),
                new Unindexed(AttributeTypes.PEER),
                new Unindexed(AttributeTypes.PEERING),
                new IndexWithValue(AttributeTypes.PEERING_SET, "peering_set", "peering_set"),
                new IndexWithNameAndType(AttributeTypes.PERSON, ObjectType.PERSON, "names"),
                new Unindexed(AttributeTypes.PHONE),
                new IndexWithReference(AttributeTypes.PING_HDL, "ping_hdl", "pe_ro_id"),
                new Unindexed(AttributeTypes.PINGABLE),
                new IndexWithValue(AttributeTypes.POEM, "poem", "poem"),
                new IndexWithValue(AttributeTypes.POETIC_FORM, "poetic_form", "poetic_form"),
                new IndexWithReference(AttributeTypes.REFERRAL_BY, "referral_by", "mnt_id"),
                new IndexWithValue(AttributeTypes.REF_NFY, "ref_nfy", "ref_nfy"),
                new Unindexed(AttributeTypes.REMARKS),
                new IndexWithNameAndType(AttributeTypes.ROLE, ObjectType.ROLE, "names"),
                new IndexWithRoute(AttributeTypes.ROUTE),
                new IndexWithRoute6(AttributeTypes.ROUTE6),
                new IndexWithValue(AttributeTypes.ROUTE_SET, "route_set", "route_set"),
                new IndexWithValue(AttributeTypes.RTR_SET, "rtr_set", "rtr_set"),
                new Unindexed(AttributeTypes.SIGNATURE),
                new Unindexed(AttributeTypes.SOURCE),
                new Unindexed(AttributeTypes.STATUS),
                new IndexWithReference(AttributeTypes.TECH_C, "tech_c", "pe_ro_id"),
                new Unindexed(AttributeTypes.TEXT),
                new IndexWithValue(AttributeTypes.UPD_TO, "upd_to", "upd_to"),
                new IndexWithReference(AttributeTypes.ZONE_C, "zone_c", "pe_ro_id")
        };

        final Map<AttributeType, IndexStrategy> indexByAttribute = Maps.newHashMap();
        for (final IndexStrategy indexStrategy : indexStrategies) {
            final AttributeType attributeType = indexStrategy.getAttributeType();
            final IndexStrategy previous = indexByAttribute.put(attributeType, indexStrategy);
            Validate.isTrue(previous == null, "Multiple definitions for: " + attributeType);
        }
        INDEX_BY_ATTRIBUTE = Collections.unmodifiableMap(indexByAttribute);

        final Map<ObjectType, List<IndexStrategy>> indexesReferingObject = Maps.newEnumMap(ObjectType.class);
        for (final ObjectType objectType : ObjectType.values()) {
            final List<IndexStrategy> indexesRefererringCurrentObject = Lists.newArrayList();
            for (final IndexStrategy indexStrategy : indexStrategies) {
                if (indexStrategy.getAttributeType().getReferences().contains(objectType)) {
                    indexesRefererringCurrentObject.add(indexStrategy);
                }
            }

            indexesReferingObject.put(objectType, Collections.unmodifiableList(indexesRefererringCurrentObject));
        }
        INDEXES_REFERING_OBJECT = Collections.unmodifiableMap(indexesReferingObject);
    }

    private IndexStrategies() {
    }

    public static IndexStrategy get(final AttributeType attributeType) {
        return INDEX_BY_ATTRIBUTE.get(attributeType);
    }

    public static List<IndexStrategy> getReferencing(final ObjectType objectType) {
        return INDEXES_REFERING_OBJECT.get(objectType);
    }
}
