import 'package:flutter/material.dart';

class PrintScreen extends StatefulWidget {
  const PrintScreen({super.key});

  static const route = '/print';

  @override
  State<PrintScreen> createState() => _PrintScreenState();
}

class _PrintScreenState extends State<PrintScreen> {
  final _barcode = TextEditingController();
  int _copies = 1;
  String _template = 'parcel';
  String? _status;

  @override
  void dispose() {
    _barcode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Print label')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _barcode,
            decoration: const InputDecoration(labelText: 'Parcel barcode'),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: _template,
            items: const [
              DropdownMenuItem(value: 'parcel', child: Text('Parcel label')),
              DropdownMenuItem(value: 'returns', child: Text('Returns label')),
              DropdownMenuItem(value: 'bin', child: Text('Bin label')),
            ],
            onChanged: (v) => setState(() => _template = v ?? 'parcel'),
            decoration: const InputDecoration(labelText: 'Template'),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              const Text('Copies'),
              IconButton(
                onPressed: _copies > 1 ? () => setState(() => _copies--) : null,
                icon: const Icon(Icons.remove),
              ),
              Text('$_copies'),
              IconButton(
                onPressed: _copies < 10
                    ? () => setState(() => _copies++)
                    : null,
                icon: const Icon(Icons.add),
              ),
            ],
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: () => setState(
              () => _status = 'Sent ${_barcode.text} ($_template) x$_copies',
            ),
            child: const Text('Print'),
          ),
          if (_status != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(_status!),
            ),
        ],
      ),
    );
  }
}
