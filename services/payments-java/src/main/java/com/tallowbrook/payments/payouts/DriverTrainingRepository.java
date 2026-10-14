package com.tallowbrook.payments.payouts;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DriverTrainingRepository extends JpaRepository<TrainingCertificate, Long> {

    List<TrainingCertificate> findByDriverIdAndCourseCode(String driverId, String courseCode);
}
