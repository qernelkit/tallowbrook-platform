import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

/// The handhelds' yellow scan button arrives as a key event. Wrap the scan screen in
/// this to start and stop the imager with it.
class ScanTrigger extends StatelessWidget {
  const ScanTrigger({
    super.key,
    required this.onPressed,
    required this.onReleased,
    required this.child,
  });

  /// Key codes the handheld vendors use for the side and pistol-grip triggers.
  static final triggerKeys = <PhysicalKeyboardKey>{
    PhysicalKeyboardKey(0x00070068),
    PhysicalKeyboardKey(0x00070069),
  };

  final VoidCallback onPressed;
  final VoidCallback onReleased;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Focus(autofocus: true, onKeyEvent: _onTrigger, child: child);
  }

  KeyEventResult _onTrigger(FocusNode node, KeyEvent event) {
    if (!triggerKeys.contains(event.physicalKey)) {
      return KeyEventResult.ignored;
    }
    if (event is KeyDownEvent) {
      onPressed();
    } else if (event is KeyUpEvent) {
      onReleased();
    }
    return KeyEventResult.handled;
  }
}
