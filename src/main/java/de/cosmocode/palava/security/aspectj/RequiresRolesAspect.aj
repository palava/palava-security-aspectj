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
