package net.ripe.db.whois.update.authentication.strategy;

import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import net.ripe.db.whois.update.authentication.credential.AuthenticationModule;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class RouteAutnumAuthentication extends RouteAuthentication {

    @Autowired
    public RouteAutnumAuthentication(final AuthenticationModule authenticationModule, final RpslObjectDao objectDao) {
        super(authenticationModule, objectDao);
    }

    @Override
    public List<RpslObject> authenticate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject updatedObject = update.getUpdatedObject();
        final CIString origin = updatedObject.getValueForAttribute(AttributeTypes.ORIGIN);

        final RpslObject autNum = getAutNum(updatedObject, origin);
        if (autNum.containsAttribute(AttributeTypes.MNT_ROUTES)) {
            final List<RpslObject> candidates = getCandidatesForMntRoutesAuthentication(autNum, update);
            final List<RpslObject> authenticated = authenticationModule.authenticate(update, updateContext, candidates);
            if (authenticated.isEmpty()) {
                throw new AuthenticationFailedException(UpdateMessages.authenticationFailed(autNum, AttributeTypes.MNT_ROUTES, candidates), candidates);
            }

            return authenticated;
        }

        final List<RpslObject> candidates = objectDao.getByKeys(ObjectType.MNTNER, autNum.getValuesForAttribute(AttributeTypes.MNT_BY));
        final List<RpslObject> authenticated = authenticationModule.authenticate(update, updateContext, candidates);
        if (authenticated.isEmpty()) {
            throw new AuthenticationFailedException(UpdateMessages.authenticationFailed(autNum, AttributeTypes.MNT_BY, candidates), candidates);
        }

        return authenticated;
    }

    private RpslObject getAutNum(final RpslObject updatedObject, final CIString origin) {
        try {
            return objectDao.getByKey(ObjectType.AUT_NUM, origin.toString());
        } catch (EmptyResultDataAccessException ignored) {
            throw new AuthenticationFailedException(UpdateMessages.authenticationFailed(updatedObject, AttributeTypes.ORIGIN, Collections.<RpslObject>emptyList()), Collections.<RpslObject>emptyList());
        }
    }
}
