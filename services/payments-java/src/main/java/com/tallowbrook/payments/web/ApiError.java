package com.tallowbrook.payments.web;

import java.time.Instant;
import java.util.List;

public record ApiError(Instant at, int status, String error, List<String> details) {

    public static ApiError of(int status, String error, List<String> details) {
        return new ApiError(Instant.now(), status, error, List.copyOf(details));
    }
}
