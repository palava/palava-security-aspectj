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
