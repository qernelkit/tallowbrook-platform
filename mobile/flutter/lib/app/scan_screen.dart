import 'package:flutter/material.dart';

import '../scanning/scan_record.dart';
import '../scanning/scan_trigger.dart';
import 'queue_screen.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  static const route = '/scan';

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  ScanAction _action = ScanAction.toBin;
  final _target = TextEditingController();
  final List<String> _recent = [];
  bool _imagerOn = false;

  @override
  void dispose() {
    _target.dispose();
    super.dispose();
  }

  void _onBarcode(String barcode) {
    if (!isTallowbrookBarcode(barcode)) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Not a Tallowbrook label: $barcode')),
      );
      return;
    }
    setState(() => _recent.insert(0, barcode));
  }

  @override
  Widget build(BuildContext context) {
    return ScanTrigger(
      onPressed: () => setState(() => _imagerOn = true),
      onReleased: () => setState(() => _imagerOn = false),
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Scan'),
          actions: [
            IconButton(
              icon: const Icon(Icons.cloud_upload_outlined),
              onPressed: () =>
                  Navigator.of(context).pushNamed(QueueScreen.route),
            ),
          ],
        ),
        body: Column(
          children: [
            SegmentedButton<ScanAction>(
              segments: const [
                ButtonSegment(value: ScanAction.inbound, label: Text('In')),
                ButtonSegment(value: ScanAction.toBin, label: Text('Bin')),
                ButtonSegment(value: ScanAction.toTruck, label: Text('Truck')),
                ButtonSegment(value: ScanAction.damage, label: Text('Damage')),
              ],
              selected: {_action},
              onSelectionChanged: (s) => setState(() => _action = s.first),
            ),
            if (_action == ScanAction.toBin || _action == ScanAction.toTruck)
              Padding(
                padding: const EdgeInsets.all(12),
                child: TextField(
                  controller: _target,
                  decoration: InputDecoration(
                    labelText: _action == ScanAction.toBin ? 'Bin' : 'Truck',
                  ),
                ),
              ),
            ListTile(
              leading: Icon(_imagerOn ? Icons.qr_code_scanner : Icons.qr_code),
              title: Text(
                _imagerOn ? 'Scanning…' : 'Press the trigger to scan',
              ),
              onTap: () => _onBarcode('TB000000000GB'),
            ),
            const Divider(),
            Expanded(
              child: ListView.builder(
                itemCount: _recent.length,
                itemBuilder: (_, i) =>
                    ListTile(dense: true, title: Text(_recent[i])),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
