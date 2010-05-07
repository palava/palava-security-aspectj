/**
 * Copyright 2010 CosmoCode GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final aspect RequiresGuestAspect extends AbstractSecurityAspect issingleton() {

    private static final Logger LOG = LoggerFactory.getLogger(RequiresGuestAspect.class);

    pointcut requiresGuest(): execution(@RequiresGuest * *.*(..));
    
    before(): requiresGuest() {
        final Subject currentUser = getCurrentUser();
        if (currentUser.isAuthenticated()) {
            throw new AuthenticationException(String.format(
                "%s is not accessible to authenticated users", thisJoinPointStaticPart.getSignature()
            ));
        } else if (currentUser.isRemembered()) {
            throw new AuthenticationException(String.format(
                "%s is not accessible to remembered user", thisJoinPointStaticPart.getSignature()
            ));
        } else {
            LOG.trace("{} is neither authenticated nor remembered and therefore allowed to exectue",
                currentUser, thisJoinPointStaticPart.getSignature()
            );
        }
    }
    
}
