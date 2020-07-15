library argon2_ffi_base;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names,

typedef Argon2HashNative = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  Uint32 keyLen,
  Pointer<Uint8> salt,
  Uint32 saltlen,
  Uint32 m_cost, // memory cost
  Uint32 t_cost, // time cost (number iterations)
  Uint32 parallelism,
  IntPtr hashlen,
  Uint8 type,
  Uint32 version,
);

typedef Argon2Hash = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> salt,
  int saltlen,
  int m_cost, // memory cost
  int t_cost, // time cost (number iterations)
  int parallelism,
  int hashlen,
  int type,
  int version,
);

class Argon2FfiFlutter extends Argon2Base {
  Argon2FfiFlutter() {
    final argon2lib = Platform.isAndroid
        ? DynamicLibrary.open('libargon2_ffi.so')
        : Platform.isLinux
            ? DynamicLibrary.open('libargon2_ffi_plugin.so')
            : Platform.isWindows
                ? DynamicLibrary.open('argon2_ffi_plugin.dll')
                : DynamicLibrary.executable();
    _nativeAdd = argon2lib
        .lookup<NativeFunction<Int32 Function(Int32, Int32)>>('native_add')
        .asFunction();
    argon2hash = argon2lib
        .lookup<NativeFunction<Argon2HashNative>>('hp_argon2_hash')
        .asFunction();
  }

  int Function(int x, int y) _nativeAdd;
  @override
  Argon2Hash argon2hash;

  int addIt(int x, int y) => _nativeAdd(x, y);
}

abstract class Argon2 {
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

abstract class Argon2Base extends Argon2 {
//  @protected
  Argon2Hash get argon2hash;

  @override
  Uint8List argon2(Argon2Arguments args) {
    final keyPtr = Uint8ArrayUtils.toPointer(args.key);
    final saltPtr = Uint8ArrayUtils.toPointer(args.salt);
//    final saltArray = allocate<Uint8>(count: args.salt.length);
//    final saltList = saltArray.asTypedList(args.length);
//    saltList.setAll(0, args.salt);
//    const memoryCost = 1 << 16;

//    _logger.fine('saltArray: ${ByteUtils.toHexList(saltArray.view)}');

    final result = argon2hash(
      keyPtr,
      args.key.length,
      saltPtr,
      args.salt.length,
      args.memory,
      args.iterations,
      args.parallelism,
      args.length,
      args.type,
      args.version,
    );

    free(keyPtr);
    free(saltPtr);
//    free(saltArray);
    final resultString = Utf8.fromUtf8(result);
    return base64.decode(resultString);
  }

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) async {
    return argon2(args);
  }
}

// from https://github.com/hanabi1224/flutter_native_extensions/blob/master/src/compression/dart_native_compression/lib/utils/uint8_list_utils.dart
class Uint8ArrayUtils {
  static Uint8List fromPointer(Pointer<Uint8> ptr, int length) {
    final view = ptr.asTypedList(length);
    final builder = BytesBuilder(copy: false);
    builder.add(view);
    return builder.takeBytes();
  }

  static Pointer<Uint8> toPointer(Uint8List bytes) {
    final ptr = allocate<Uint8>(count: bytes.length);
    final byteList = ptr.asTypedList(bytes.length);
    byteList.setAll(0, bytes);
    return ptr.cast();
  }
}
