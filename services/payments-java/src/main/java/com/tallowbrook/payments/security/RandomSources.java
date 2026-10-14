package com.tallowbrook.payments.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/** The one random source the service injects wherever it needs IVs, salts or keys. */
@Configuration
public class RandomSources {

    private static final byte[] PERSONALIZATION =
            "tallowbrook-payments".getBytes(StandardCharsets.US_ASCII);

    @Bean
    SecureRandom paymentsRandom() throws NoSuchAlgorithmException {
        return SecureRandom.getInstance(
                "DRBG",
                DrbgParameters.instantiation(256, Capability.PR_AND_RESEED, PERSONALIZATION));
    }
}
