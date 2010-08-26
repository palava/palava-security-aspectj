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

import java.util.Arrays;

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
                subject.checkPermissions("access");
                EasyMock.expectLastCall().andStubThrow(new AuthorizationException());
                subject.checkRoles(Arrays.asList("admin"));
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
