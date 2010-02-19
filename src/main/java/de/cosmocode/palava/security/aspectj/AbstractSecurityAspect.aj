package de.cosmocode.palava.security.aspectj;

import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Guice;
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
