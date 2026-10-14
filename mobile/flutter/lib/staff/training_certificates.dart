/// Forklift and dangerous-goods training records. A task that needs a forklift or
/// handles hazmat parcels is only offered to staff whose training is current.
enum TrainingKind { counterbalance, reachTruck, dangerousGoods }

class ForkliftCertificate {
  ForkliftCertificate({
    required this.staffId,
    required this.kind,
    required this.licenceNumber,
    required this.issuedOn,
    required this.expiresOn,
  });

  factory ForkliftCertificate.fromJson(Map<String, Object?> json) =>
      ForkliftCertificate(
        staffId: json['staff_id']! as String,
        kind: TrainingKind.values.byName(json['kind']! as String),
        licenceNumber: json['licence']! as String,
        issuedOn: DateTime.parse(json['issued_on']! as String),
        expiresOn: DateTime.parse(json['expires_on']! as String),
      );

  final String staffId;
  final TrainingKind kind;
  final String licenceNumber;
  final DateTime issuedOn;
  final DateTime expiresOn;

  bool isCurrentOn(DateTime day) =>
      !day.isBefore(issuedOn) && day.isBefore(expiresOn);

  /// Reminders go out four weeks before a licence lapses.
  bool needsRenewalReminder(DateTime today) =>
      isCurrentOn(today) &&
      expiresOn.difference(today) <= const Duration(days: 28);
}

class TrainingRecords {
  TrainingRecords(this._records);

  final List<ForkliftCertificate> _records;

  bool mayOperate(String staffId, TrainingKind kind, DateTime today) =>
      _records.any(
        (r) => r.staffId == staffId && r.kind == kind && r.isCurrentOn(today),
      );

  Iterable<String> staffNeedingReminders(DateTime today) => _records
      .where((r) => r.needsRenewalReminder(today))
      .map((r) => r.staffId)
      .toSet();
}
