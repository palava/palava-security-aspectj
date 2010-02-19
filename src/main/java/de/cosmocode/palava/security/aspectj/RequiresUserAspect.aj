package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final aspect RequiresUserAspect extends AbstractSecurityAspect {

    private static final Logger LOG = LoggerFactory.getLogger(RequiresUserAspect.class);

    pointcut requiresUser(): execution(@RequiresUser * *.*(..));
    
    before(): requiresUser() {
        final Subject currentUser = getCurrentUser();
        if (currentUser.isAuthenticated()) {
            LOG.trace("{} is authenticated and therefore allowed to access {}",
                currentUser,
                thisJoinPointStaticPart.getSignature()
            );
        } else if (currentUser.isRemembered()) {
            LOG.trace("{} is remembered and therefore allowed to access {}",
                currentUser,
                thisJoinPointStaticPart.getSignature()
            );
        } else {
            throw new AuthenticationException(String.format(
                "%s is only accessible to authenticated or remembered users", thisJoinPointStaticPart.getSignature()
            ));
        }
    }
    
}
