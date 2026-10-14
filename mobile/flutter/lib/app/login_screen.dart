import 'package:flutter/material.dart';

import '../security/staff_pin.dart';
import 'scan_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  static const route = '/';

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _staffId = TextEditingController();
  final _pin = TextEditingController();
  final _staffPin = StaffPin();
  String? _error;
  bool _checking = false;

  @override
  void dispose() {
    _staffId.dispose();
    _pin.dispose();
    super.dispose();
  }

  Future<void> _signIn() async {
    setState(() {
      _checking = true;
      _error = null;
    });
    final verifier = await DeviceProfile.verifierFor(_staffId.text.trim());
    final ok = verifier != null && await _staffPin.check(_pin.text, verifier);
    if (!mounted) {
      return;
    }
    setState(() => _checking = false);
    if (ok) {
      await Navigator.of(context).pushReplacementNamed(ScanScreen.route);
    } else {
      setState(
        () => _error = _staffPin.lockedOut
            ? 'Too many attempts. Ask your supervisor.'
            : 'Staff ID or PIN not recognised.',
      );
      _pin.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign in')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _staffId,
              decoration: const InputDecoration(labelText: 'Staff ID'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _pin,
              decoration: const InputDecoration(labelText: 'PIN'),
              keyboardType: TextInputType.number,
              obscureText: true,
              maxLength: StaffPin.length,
            ),
            if (_error != null)
              Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            const SizedBox(height: 24),
            FilledButton(
              onPressed: _checking ? null : _signIn,
              child: Text(_checking ? 'Checking…' : 'Sign in'),
            ),
          ],
        ),
      ),
    );
  }
}

/// PIN verifiers provisioned to this handheld for the depot's staff.
class DeviceProfile {
  static final Map<String, PinVerifier> _verifiers = {};

  static void load(Map<String, Object?> json) {
    _verifiers
      ..clear()
      ..addAll(
        json.map(
          (id, v) =>
              MapEntry(id, PinVerifier.fromJson(v! as Map<String, Object?>)),
        ),
      );
  }

  static Future<PinVerifier?> verifierFor(String staffId) async =>
      _verifiers[staffId];
}
