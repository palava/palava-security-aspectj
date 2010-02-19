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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.Subject;
import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.inject.Binder;
import com.google.inject.Guice;
import com.google.inject.Module;

/**
 * Dummy services with secured methods.
 *
 * @author Willi Schoenborn
 */
public final class SecurityTest {

    /**
     * Runs before class und binds a dummy subject.
     */
    @BeforeClass
    public static void beforeClass() {
        Guice.createInjector(new Module() {
            
            @Override
            public void configure(Binder binder) {
                final Subject subject = EasyMock.createMock("subject", Subject.class);
                EasyMock.expect(subject.isAuthenticated()).andStubReturn(false);
                EasyMock.expect(subject.isRemembered()).andStubReturn(false);
                subject.checkPermission("access");
                EasyMock.expectLastCall().andStubThrow(new AuthorizationException());
                subject.checkRole("admin");
                EasyMock.expectLastCall().andStubThrow(new AuthorizationException());
                EasyMock.replay(subject);
                binder.bind(Subject.class).toInstance(subject);  
            }
            
        });
    }
    
    /**
     * Tests {@link RequiresGuestAspect}.
     */
    @Test
    @RequiresGuest
    public void guestsOnly() {
        
    }

    /**
     * Tests {@link RequiresUserAspect}.
     */
    @Test(expected = AuthenticationException.class)
    @RequiresUser
    public void usersOnly() {
        
    }

    /**
     * Tests {@link RequiresAuthenticationAspect}.
     */
    @Test(expected = AuthenticationException.class)
    @RequiresAuthentication
    public void authenticatedOnly() {
        
    }

    /**
     * Tests {@link RequiresPermissionsAspect}.
     */
    @Test(expected = AuthorizationException.class)
    @RequiresPermissions("access")
    public void permissionOnly() {
        
    }

    /**
     * Tests {@link RequiresRolesAspect}.
     */
    @Test(expected = AuthorizationException.class)
    @RequiresRoles("admin")
    public void roleOnly() {
        
    }
    
}
