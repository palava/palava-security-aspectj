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

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dummy services with secured methods.
 *
 * @author Willi Schoenborn
 */
public final class SecureDummyService {

    private static final Logger LOG = LoggerFactory.getLogger(SecureDummyService.class);

    @RequiresGuest
    public void getAnonymousInfo() {
        
    }
    
    @RequiresUser
    public void getMyInfo() {
        
    }
    
    @RequiresAuthentication
    public void getSecretInfo() {
        
    }
    
    @RequiresPermissions("asset:upload")
    public boolean deleteAll() {
        return true;
    }
    
    @RequiresRoles("admin")
    public boolean dropDatabase() {
        return true;
    }
    
}
