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
