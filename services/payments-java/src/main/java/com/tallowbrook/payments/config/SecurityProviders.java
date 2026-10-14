package com.tallowbrook.payments.config;

import jakarta.annotation.PostConstruct;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

/**
 * Registers the Bouncy Castle JCA provider at start-up. LotusPay and the regional acquirer need
 * algorithms the JDK providers do not ship.
 */
@Configuration
public class SecurityProviders {

    private static final Logger log = LoggerFactory.getLogger(SecurityProviders.class);

    @PostConstruct
    void register() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            log.info("Registered additional JCA provider");
        }
    }
}
