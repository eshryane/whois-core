package net.ripe.db.whois.update.autokey;

import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.ValidationMessages;
import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import net.ripe.db.whois.update.autokey.dao.OrganisationIdRepository;
import net.ripe.db.whois.update.domain.OrganisationId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class OrganisationIdFactory extends AbstractAutoKeyFactory<OrganisationId> {

    @Autowired
    public OrganisationIdFactory(final OrganisationIdRepository organisationIdRepository) {
        super(organisationIdRepository);
    }

    @Override
    public AttributeType getAttributeType() {
        return AttributeTypes.ORGANISATION;
    }

    @Override
    public OrganisationId generate(final String keyPlaceHolder, final RpslObject object) {
        return generateForName(keyPlaceHolder, object.getValueForAttribute(AttributeTypes.ORG_NAME).toString());
    }

    @Override
    public OrganisationId claim(final String key) throws ClaimException {
        throw new ClaimException(ValidationMessages.syntaxError(key));
    }
}
