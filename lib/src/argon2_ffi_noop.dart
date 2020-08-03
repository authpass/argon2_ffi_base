import 'dart:typed_data';

import 'package:argon2_ffi_base/src/argon2_ffi_base.dart';

class Argon2FfiFlutter extends Argon2 {
  @override
  Uint8List argon2(Argon2Arguments args) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) {
    throw UnimplementedError();
  }
}
