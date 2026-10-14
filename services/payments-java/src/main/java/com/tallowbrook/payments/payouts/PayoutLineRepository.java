package com.tallowbrook.payments.payouts;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PayoutLineRepository extends JpaRepository<PayoutLine, Long> {

    List<PayoutLine> findByRunIdOrderByDriverIdAsc(String runId);
}
