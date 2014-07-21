package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.ip.IpInterval;
import net.ripe.db.whois.common.iptree.IpEntry;
import net.ripe.db.whois.common.iptree.IpTree;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import net.ripe.db.whois.common.rpsl.attrs.InetStatus;
import net.ripe.db.whois.common.rpsl.attrs.InetnumStatus;
import net.ripe.db.whois.update.authentication.Principal;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.CheckForNull;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static net.ripe.db.whois.update.handler.validator.inetnum.InetStatusHelper.getStatus;

@Component
public class StatusValidator implements BusinessRuleValidator { // TODO [AK] Redesign status validator using subtrees: parent or child intervals should not have different validation logic, the tree must be valid as a whole
    private final RpslObjectDao objectDao;
    private final Ipv4Tree ipv4Tree;
    private final Ipv6Tree ipv6Tree;
    private final Maintainers maintainers;
    private static final CIString NOT_SET = CIString.ciString("NOT-SET");

    @Autowired
    public StatusValidator(
            final RpslObjectDao objectDao,
            final Ipv4Tree ipv4Tree,
            final Ipv6Tree ipv6Tree,
            final Maintainers maintainers) {
        this.objectDao = objectDao;
        this.ipv4Tree = ipv4Tree;
        this.ipv6Tree = ipv6Tree;
        this.maintainers = maintainers;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY, Action.DELETE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.INETNUM, ObjectType.INET6NUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        if (updateContext.getSubject(update).hasPrincipal(Principal.OVERRIDE_MAINTAINER)) {
            return;
        }

        if (update.getAction().equals(Action.CREATE)) {
            validateCreate(update, updateContext);
        } else if (update.getAction().equals(Action.DELETE)) {
            validateDelete(update, updateContext, ipv4Tree);
        } else {
            validateModify(update, updateContext);
        }
    }

    private void validateCreate(final PreparedUpdate update, final UpdateContext updateContext) {
        final IpInterval ipInterval = IpInterval.parse(update.getUpdatedObject().getKey());
        if (update.getType().equals(ObjectType.INETNUM)) {
            validateCreate(update, updateContext, ipv4Tree, ipInterval);
        } else {
            validateCreate(update, updateContext, ipv6Tree, ipInterval);
        }
    }

    @SuppressWarnings("unchecked")
    private void validateCreate(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree, final IpInterval ipInterval) {
        final RpslObject updatedObject = update.getUpdatedObject();
        if (!allChildrenHaveCorrectStatus(update, updateContext, ipTree, ipInterval)) {
            return;
        }

        final CIString statusValue = updatedObject.getValueForAttribute(AttributeTypes.STATUS);
        if (statusValue.equals(NOT_SET)) {
            updateContext.addMessage(update, UpdateMessages.statusRequiresAuthorization(NOT_SET.toString()));
        } else {
            final InetStatus currentStatus = InetStatusHelper.getStatus(update);
            final List<IpEntry> parents = ipTree.findFirstLessSpecific(ipInterval);
            if (parents.size() != 1) {
                updateContext.addMessage(update, UpdateMessages.invalidParentEntryForInterval(ipInterval));
                return;
            }
            checkAuthorisationForStatus(update, updateContext, updatedObject, currentStatus);

            final RpslObject parentObject = objectDao.getById(parents.get(0).getObjectId());
            final List<RpslAttribute> parentStatuses = parentObject.findAttributes(AttributeTypes.STATUS);
            if (parentStatuses.isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.objectLacksStatus("Parent", parentObject.getKey()));
                return;
            }

            final InetStatus parentStatus = InetStatusHelper.getStatus(parentObject);
            if (parentStatus == null) {
                updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Parent", parentObject.getKey(), parentObject.getValueForAttribute(AttributeTypes.STATUS)));
                return;
            }

            final Set<CIString> updateMntBy = updatedObject.getValuesForAttribute(AttributeTypes.MNT_BY);
            final boolean hasRsMaintainer = !Sets.intersection(maintainers.getRsMaintainers(), updateMntBy).isEmpty();

            if (currentStatus.equals(InetnumStatus.ASSIGNED_PA) && parentStatus.equals(InetnumStatus.ASSIGNED_PA)) {
                checkAuthorizationForStatusInHierarchy(update, updateContext, ipTree, ipInterval, UpdateMessages.incorrectParentStatus(updatedObject.getType(), parentStatus.toString()));
            } else if (!currentStatus.worksWithParentStatus(parentStatus, hasRsMaintainer)) {
                updateContext.addMessage(update, UpdateMessages.incorrectParentStatus(updatedObject.getType(), parentStatus.toString()));
            }

            if (currentStatus.equals(InetnumStatus.ASSIGNED_PI)) {
                if (parentStatus.equals(InetnumStatus.ASSIGNED_PI)) {
                    final Set<CIString> parentMntBy = parentObject.getValuesForAttribute(AttributeTypes.MNT_BY);
                    final boolean parentHasRsMaintainer = !Sets.intersection(maintainers.getRsMaintainers(), parentMntBy).isEmpty();
                    if (parentHasRsMaintainer) {
                        updateContext.addMessage(update, UpdateMessages.incorrectParentStatus(updatedObject.getType(), parentStatus.toString()));
                    }
                }

                checkAuthorizationForStatusInHierarchy(update, updateContext, ipTree, ipInterval, UpdateMessages.incorrectParentStatus(updatedObject.getType(), parentStatus.toString()));
            }
        }
    }

    private boolean authByRsOrOverride(final Subject subject) {
        return subject.hasPrincipal(Principal.RS_MAINTAINER) || subject.hasPrincipal(Principal.OVERRIDE_MAINTAINER);
    }

    private void checkAuthorizationForStatusInHierarchy(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree, final IpInterval ipInterval, final Message errorMessage) {
        final RpslObject parentInHierarchyMaintainedByRs = findParentWithRsMaintainer(ipTree, ipInterval);

        if (parentInHierarchyMaintainedByRs != null) {

            final List<RpslAttribute> parentStatuses = parentInHierarchyMaintainedByRs.findAttributes(AttributeTypes.STATUS);
            if (parentStatuses.isEmpty()) {
                return;
            }

            final CIString parentStatusValue = parentStatuses.get(0).getCleanValue();
            final InetStatus parentStatus = getStatus(parentStatusValue, update);

            if (parentStatus == null) {
                updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Parent", parentInHierarchyMaintainedByRs.getKey(), parentStatusValue));
            } else {
                final Set<CIString> mntLower = parentInHierarchyMaintainedByRs.getValuesForAttribute(AttributeTypes.MNT_LOWER);
                final boolean parentHasRsMntLower = !Sets.intersection(maintainers.getRsMaintainers(), mntLower).isEmpty();
                final InetStatus currentStatus = InetStatusHelper.getStatus(update);

                if (!currentStatus.worksWithParentInHierarchy(parentStatus, parentHasRsMntLower)) {
                    updateContext.addMessage(update, errorMessage);
                }
            }
        }
    }

    @CheckForNull
    private RpslObject findParentWithRsMaintainer(final IpTree ipTree, final IpInterval ipInterval) {
        @SuppressWarnings("unchecked")
        final List<IpEntry> allLessSpecific = Lists.reverse(ipTree.findAllLessSpecific(ipInterval));
        for (final IpEntry parent : allLessSpecific) {
            final RpslObject parentObject = objectDao.getById(parent.getObjectId());
            final Set<CIString> mntBy = parentObject.getValuesForAttribute(AttributeTypes.MNT_BY);

            final boolean missingRsMaintainer = Sets.intersection(maintainers.getRsMaintainers(), mntBy).isEmpty();
            if (!missingRsMaintainer) {
                return parentObject;
            }
        }

        return null;
    }

    private void checkAuthorisationForStatus(final PreparedUpdate update, final UpdateContext updateContext, final RpslObject updatedObject, final InetStatus currentStatus) {
        final Set<CIString> mntBy = updatedObject.getValuesForAttribute(AttributeTypes.MNT_BY);

        if (currentStatus.requiresAllocMaintainer()) {
            final boolean hasOnlyAllocMaintainer = Sets.intersection(maintainers.getAllocMaintainers(), mntBy).containsAll(mntBy);
            if (!hasOnlyAllocMaintainer) {
                updateContext.addMessage(update, UpdateMessages.statusRequiresAuthorization(currentStatus.toString()));
                return;
            }
            if (!updateContext.getSubject(update).hasPrincipal(Principal.ALLOC_MAINTAINER)) {
                updateContext.addMessage(update, UpdateMessages.statusRequiresAuthorization(currentStatus.toString()));
                return;
            }
        }

        if (currentStatus.requiresRsMaintainer()) {
            final boolean missingRsMaintainer = Sets.intersection(maintainers.getRsMaintainers(), mntBy).isEmpty();
            if (missingRsMaintainer) {
                updateContext.addMessage(update, UpdateMessages.statusRequiresAuthorization(updatedObject.getValueForAttribute(AttributeTypes.STATUS).toString()));
                return;
            }
            if (!updateContext.getSubject(update).hasPrincipal(Principal.RS_MAINTAINER)) {
                updateContext.addMessage(update, UpdateMessages.authorisationRequiredForSetStatus(currentStatus.toString()));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean allChildrenHaveCorrectStatus(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree, final IpInterval ipInterval) {
        final List<IpEntry> children = ipTree.findFirstMoreSpecific(ipInterval);
        final RpslAttribute updateStatusAttribute = update.getUpdatedObject().findAttribute(AttributeTypes.STATUS);
        final InetStatus updatedStatus = InetStatusHelper.getStatus(update);

        for (final IpEntry child : children) {
            final RpslObject childObject = objectDao.getById(child.getObjectId());
            final List<RpslAttribute> childStatuses = childObject.findAttributes(AttributeTypes.STATUS);
            if (childStatuses.isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.objectLacksStatus("Child", childObject.getKey()));
                continue;
            }

            final CIString childStatusValue = childStatuses.get(0).getCleanValue();
            final InetStatus childStatus = getStatus(childStatusValue, update);
            if (childStatus == null) {
                updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Child", childObject.getKey(), childStatusValue));
                return false;
            }
            final Set<CIString> childMntBy = childObject.getValuesForAttribute(AttributeTypes.MNT_BY);
            final boolean hasRsMaintainer = !Sets.intersection(maintainers.getRsMaintainers(), childMntBy).isEmpty();

            if (!childStatus.worksWithParentStatus(updatedStatus, hasRsMaintainer)) {
                updateContext.addMessage(update, UpdateMessages.incorrectChildStatus(updateStatusAttribute.getCleanValue(), childStatusValue, childObject.getKey()));
                return false;
            } else if (updatedStatus.equals(InetnumStatus.ASSIGNED_PA) && childStatus.equals(InetnumStatus.ASSIGNED_PA)) {
                checkAuthorizationForStatusInHierarchy(update, updateContext, ipTree, ipInterval, UpdateMessages.incorrectChildStatus(updateStatusAttribute.getCleanValue(), childStatusValue, childObject.getKey()));
            }
        }
        return true;
    }

    private void validateModify(final PreparedUpdate update, final UpdateContext updateContext) {
        final CIString originalStatus = update.getReferenceObject() != null ? update.getReferenceObject().getValueForAttribute(AttributeTypes.STATUS) : null;
        final CIString updateStatus = update.getUpdatedObject() != null ? update.getUpdatedObject().getValueForAttribute(AttributeTypes.STATUS) : null;


        if (!Objects.equals(originalStatus, updateStatus)) {
            updateContext.addMessage(update, UpdateMessages.statusChange());
        }
    }

    private void validateDelete(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree) {
        InetStatus status;

        try {
            status = getStatus(update);
            if (status == null) {
                // invalid status attribute value
                return;
            }
        } catch (IllegalArgumentException e) {
            // status attribute not found
            return;
        }

        if (status.equals(NOT_SET)) {   //TODO will this ever succeed?
            updateContext.addMessage(update, UpdateMessages.deleteWithStatusRequiresAuthorization(NOT_SET));
            return;
        }

        if (status.requiresRsMaintainer()) {
            final Set<CIString> mntBy = update.getUpdatedObject().getValuesForAttribute(AttributeTypes.MNT_BY);
            if (Sets.intersection(maintainers.getRsMaintainers(), mntBy).isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.deleteWithStatusRequiresAuthorization(status.toString()));
            }
        }

        if (update.getUpdatedObject().getType() == ObjectType.INETNUM) {
            final IpInterval ipInterval = IpInterval.parse(update.getUpdatedObject().getKey());
            final List<IpEntry> parents = ipTree.findFirstLessSpecific(ipInterval);
            if (parents.size() != 1) {
                updateContext.addMessage(update, UpdateMessages.invalidParentEntryForInterval(ipInterval));
                return;
            }
        }
    }
}
