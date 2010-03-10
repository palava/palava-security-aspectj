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

import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provider;

abstract aspect AbstractSecurityAspect {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractSecurityAspect.class);

    private Provider<Subject> provider;

    @Inject
    void setProvider(Provider<Subject> provider) {
        this.provider = Preconditions.checkNotNull(provider, "Provider");
    }
    
    protected Subject getCurrentUser() {
        return provider.get();
    }

    pointcut createInjector(): call(Injector Guice.createInjector(..));
    
    after() returning (Injector injector): createInjector() {
        LOG.trace("Injecting members on {}", this);
        if (provider == null) {
            injector.injectMembers(this);
        } else {
            throw new IllegalStateException("An injector has already been created");
        }
    }
    
}
