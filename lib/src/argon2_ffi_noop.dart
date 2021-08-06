import 'dart:typed_data';

import 'package:argon2_ffi_base/src/argon2_ffi_base.dart';

/// This is a dummy implementation for compilation, on flutter the one
/// from `argon2_ffi_impl.dart` is used.
class Argon2FfiFlutter extends Argon2 {
  // ignore: avoid_unused_constructor_parameters
  Argon2FfiFlutter({ResolveLibrary? resolveLibrary});

  @override
  Uint8List argon2(Argon2Arguments args) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) {
    throw UnimplementedError();
  }
}
