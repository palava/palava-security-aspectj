package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final aspect RequiresRolesAspect extends AbstractSecurityAspect {

    private static final Logger LOG = LoggerFactory.getLogger(RequiresRolesAspect.class);

    pointcut requiresRoles(): execution(@RequiresRoles * *.*(..));
    
    before(RequiresRoles roles): requiresRoles() && @annotation(roles) {
        final Subject currentUser = getCurrentUser();
        final String role = roles.value();
        LOG.trace("Checking {} for role {}", currentUser, role);
        currentUser.checkRole(role);
        LOG.trace("{} has role {} and is therefore allowed to access {}", new Object[] {
            currentUser, role, thisJoinPointStaticPart.getSignature()
        });
    }
    
}
