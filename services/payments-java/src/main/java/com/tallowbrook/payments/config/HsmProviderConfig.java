package com.tallowbrook.payments.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Provider;
import java.security.Security;

/**
 * The payments HSM, reached through the JDK's SunPKCS11 provider. The token configuration file
 * (library path and slot) is owned by ops and lives outside the application jar.
 */
@Configuration
public class HsmProviderConfig {

    private static final Logger log = LoggerFactory.getLogger(HsmProviderConfig.class);

    @Bean(name = "paymentsHsm")
    Provider paymentsHsm(PaymentsProperties properties) {
        String configFile = properties.hsm().pkcs11Config().toString();
        Provider provider = Security.getProvider("SunPKCS11").configure(configFile);
        log.info("Payments token provider {} configured from {}", provider.getName(), configFile);
        return provider;
    }
}
