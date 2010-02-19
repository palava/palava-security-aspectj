package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final aspect RequiresAuthenticationAspect extends AbstractSecurityAspect issingleton() {
    
    private static final Logger LOG = LoggerFactory.getLogger(RequiresAuthenticationAspect.class);
    
    pointcut requiresAuthentication(): execution(@RequiresAuthentication * *.*(..));

    before(): requiresAuthentication() {
        final Subject currentUser = getCurrentUser();
        if (currentUser.isAuthenticated()) {
            LOG.trace("{} is authenticated and therefore allowed to execute {}", 
                currentUser, thisJoinPointStaticPart.getSignature()
            );
        } else {
            throw new AuthenticationException(String.format(
                "%s is accessible to authenticated users only", thisJoinPointStaticPart.getSignature()
            ));
        }
    }
    
}
