package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final aspect RequiresPermissionsAspect extends AbstractSecurityAspect issingleton() {

    private static final Logger LOG = LoggerFactory.getLogger(RequiresPermissionsAspect.class);

    pointcut requiresPermissions(): execution(@RequiresPermissions * *.*(..));
    
    before(RequiresPermissions permissions): requiresPermissions() && @annotation(permissions) {
        final Subject currentUser = getCurrentUser();
        final String permission = permissions.value();
        LOG.trace("Checking {} for permission {}", currentUser, permission);
        currentUser.checkPermission(permission);
        LOG.trace("{} has permission {} and is therefore allowed to access {}", new Object[] {
            currentUser, permission, thisJoinPointStaticPart.getSignature()
        });
    }
    
}
