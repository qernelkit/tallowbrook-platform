package com.tallowbrook.payments.settlement;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Settlement currency conversion. Rates are the European Central Bank's daily reference rates (EUR
 * base), read from our internal mirror of the feed.
 */
@Component
public class FxRates {

    private static final Logger log = LoggerFactory.getLogger(FxRates.class);

    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, BigDecimal> perEuro =
            new ConcurrentHashMap<>(Map.of("EUR", BigDecimal.ONE));
    private final PaymentsProperties properties;

    public FxRates(PaymentsProperties properties) {
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${tallowbrook.payments.fx.refresh:6h}")
    public void refresh() {
        URI ecbRates = URI.create(properties.fx().ecbReferenceRatesUrl());
        HttpRequest request =
                HttpRequest.newBuilder(ecbRates).timeout(Duration.ofSeconds(10)).GET().build();
        try {
            HttpResponse<InputStream> response =
                    http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                log.warn("Reference rates returned HTTP {}", response.statusCode());
                return;
            }
            try (InputStream body = response.body()) {
                parse(body);
            }
        } catch (IOException | ParserConfigurationException | SAXException e) {
            log.warn("Could not refresh reference rates: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void parse(InputStream xml)
            throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        NodeList cubes =
                factory.newDocumentBuilder().parse(xml).getElementsByTagNameNS("*", "Cube");
        for (int i = 0; i < cubes.getLength(); i++) {
            Element cube = (Element) cubes.item(i);
            if (cube.hasAttribute("currency")) {
                perEuro.put(
                        cube.getAttribute("currency"), new BigDecimal(cube.getAttribute("rate")));
            }
        }
        log.info("Loaded {} reference rates", perEuro.size());
    }

    public BigDecimal convert(BigDecimal amount, String from, String to) {
        BigDecimal fromRate = rate(from);
        BigDecimal toRate = rate(to);
        return amount.divide(fromRate, 10, RoundingMode.HALF_EVEN)
                .multiply(toRate)
                .setScale(2, RoundingMode.HALF_EVEN);
    }

    private BigDecimal rate(String currency) {
        BigDecimal rate = perEuro.get(currency);
        if (rate == null) {
            throw new IllegalArgumentException("No reference rate for " + currency);
        }
        return rate;
    }
}
