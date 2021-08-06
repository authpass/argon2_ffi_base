import 'dart:typed_data';

typedef ResolveLibrary = String Function(String baseName);

abstract class Argon2 {
  const Argon2();

  /// forces loading of dynamic library on MacOS instead of assuming
  /// argon2 was statically linked. (ie. flutter usage, vs dart usage)
  static bool resolveLibraryForceDynamic = false;

  /// flag whether it is a native (ffi) implementation, or dart.
  bool get isFfi;

  /// whether this is actually implemented or throws [UnimplementedError]
  /// (Currently on web platform).
  bool get isImplemented;

  Uint8List argon2(Argon2Arguments args);

  Future<Uint8List> argon2Async(Argon2Arguments args);
}

class Argon2Arguments {
  Argon2Arguments(this.key, this.salt, this.memory, this.iterations,
      this.length, this.parallelism, this.type, this.version);

  final Uint8List key;
  final Uint8List salt;
  final int memory;
  final int iterations;
  final int length;
  final int parallelism;
  final int type;
  final int version;
}
