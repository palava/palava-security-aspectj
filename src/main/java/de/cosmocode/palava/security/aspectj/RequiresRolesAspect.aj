/**
 * palava - a java-php-bridge
 * Copyright (C) 2007-2010  CosmoCode GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
