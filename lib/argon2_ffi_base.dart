library argon2_ffi_base;

export 'package:argon2_ffi_base/src/argon2_ffi_base.dart';
export 'package:argon2_ffi_base/src/argon2_ffi_noop.dart'
    if (dart.library.io) 'package:argon2_ffi_base/src/argon2_ffi_impl.dart';
