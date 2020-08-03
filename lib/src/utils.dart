// from https://github.com/hanabi1224/flutter_native_extensions/blob/master/src/compression/dart_native_compression/lib/utils/uint8_list_utils.dart
import 'dart:ffi';
import 'dart:io';

import 'dart:typed_data';

import 'package:ffi/ffi.dart';

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
