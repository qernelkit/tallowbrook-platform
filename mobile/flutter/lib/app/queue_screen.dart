import 'package:flutter/material.dart';

class QueueScreen extends StatefulWidget {
  const QueueScreen({super.key});

  static const route = '/queue';

  @override
  State<QueueScreen> createState() => _QueueScreenState();
}

class _QueueScreenState extends State<QueueScreen> {
  int _waiting = 0;
  DateTime? _lastUpload;
  bool _uploading = false;

  Future<void> _uploadNow() async {
    setState(() => _uploading = true);
    try {
      await QueueController.instance.flush();
      setState(() {
        _waiting = QueueController.instance.waiting;
        _lastUpload = DateTime.now();
      });
    } finally {
      if (mounted) {
        setState(() => _uploading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final last = _lastUpload;
    return Scaffold(
      appBar: AppBar(title: const Text('Upload queue')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          ListTile(
            title: const Text('Scans waiting'),
            trailing: Text('$_waiting'),
          ),
          ListTile(
            title: const Text('Last upload'),
            trailing: Text(
              last == null
                  ? 'Not yet'
                  : TimeOfDay.fromDateTime(last).format(context),
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: _uploading ? null : _uploadNow,
            icon: const Icon(Icons.cloud_upload),
            label: Text(_uploading ? 'Uploading…' : 'Upload now'),
          ),
        ],
      ),
    );
  }
}

/// Owned by the app shell; the screen only asks it to flush.
class QueueController {
  QueueController._();

  static final instance = QueueController._();

  int waiting = 0;
  Future<void> Function()? onFlush;

  Future<void> flush() async {
    await onFlush?.call();
  }
}
