package com.tallowbrook.payments.merchant;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MerchantRepository extends JpaRepository<Merchant, Long> {

    List<Merchant> findByStatus(Merchant.Status status);

    List<Merchant> findByCountryOrderByLegalNameAsc(String country);
}
