import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:argon2_ffi_base/src/argon2_ffi_base.dart';
import 'package:argon2_ffi_base/src/utils.dart';
import 'package:ffi/ffi.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;

final _logger = Logger('argon2_ffi_base');

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

abstract class Argon2Base extends Argon2 {
  const Argon2Base();

//  @protected
  Argon2Hash get argon2hash;

  @override
  bool get isFfi => true;
  @override
  bool get isImplemented => true;

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

    calloc.free(keyPtr);
    calloc.free(saltPtr);
//    free(saltArray);
    final resultString = result.toDartString();
    return base64.decode(resultString);
  }

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) async {
    return argon2(args);
  }
}

class Argon2FfiFlutter extends Argon2Base {
  Argon2FfiFlutter({this.resolveLibrary}) {
    final argon2lib = _loadLib();
    _nativeAdd = argon2lib
        .lookup<NativeFunction<Int32 Function(Int32, Int32)>>('native_add')
        .asFunction();
    argon2hash = argon2lib
        .lookup<NativeFunction<Argon2HashNative>>('hp_argon2_hash')
        .asFunction();
  }

  static ResolveLibrary defaultResolveLibrary = (name) {
    if (Platform.isLinux) {
      // on linux the library is put into a `lib` sub directory.
      _logger.finest(
          'Resolving path to $name relative to ${Platform.resolvedExecutable}');
      final appDir = File(Platform.resolvedExecutable).parent.absolute;
      final appDirPath = appDir.path;
      {
        final f = File(path.join(appDirPath, name));
        _logger.finest('checking $appDirPath for $name');
        if (f.existsSync()) {
          // library available in the same path as the executable.
          return name;
        }
      }
      _logger.finest('$name not found in current path, looking into lib/$name');
      final libSo = File(path.join(appDirPath, 'lib', name));
      if (libSo.existsSync()) {
        final ret = libSo.absolute.path;
        // final relative = '${path.relative(ret, from: cwd.path)}';
        _logger.finer('Loading from ($ret)');
        return ret;
      } else {
        _logger.severe('Unable to find $name at ${libSo.path}');
      }
    }
    return name;
  };

  final ResolveLibrary? resolveLibrary;

  late int Function(int x, int y) _nativeAdd;
  @override
  late Argon2Hash argon2hash;

  int addIt(int x, int y) => _nativeAdd(x, y);

  DynamicLibrary _loadLib() {
    final resolveLibrary = this.resolveLibrary ?? defaultResolveLibrary;

    if (!Argon2.resolveLibraryForceDynamic &&
        (Platform.isIOS || Platform.isMacOS)) {
      return DynamicLibrary.executable();
    }
    final libraryNames = [
      [Platform.isAndroid, 'libargon2_ffi.so'],
      [Platform.isLinux, './libargon2_ffi_plugin.so'],
      [Platform.isWindows, 'argon2_ffi_plugin.dll'],
      [Platform.isMacOS, 'libargon2_ffi.dylib'],
      [Platform.isIOS, null], // only supports static linking.
    ];
    final libraryName = libraryNames.firstWhere((element) => element[0] == true,
            orElse: (() => throw StateError(
                'Unsupported Operating System ${Platform.operatingSystem}')))[1]
        as String?;
    _logger.finest('resolving $libraryName');
    if (libraryName == null) {
      return DynamicLibrary.executable();
    }
    final path = resolveLibrary(libraryName);
    _logger.finest('DynamicLibrary.open($path)');
    try {
      return DynamicLibrary.open(path);
    } on ArgumentError catch (e, stackTrace) {
      _logger.severe(
          'Error while loading dynamic library from $path ($libraryName)',
          e,
          stackTrace);
      if (e.message.toString().contains('hardened programs')) {
        final message = 'Unable to load argon2 library. On MacOS you have to '
            'remove hardening from dart binary:\n\n'
            'codesign --remove-signature ${Platform.resolvedExecutable}\n\n'
            'https://github.com/dart-lang/sdk/issues/39231#issuecomment-579743656';
        _logger.shout(message);
        throw ArgumentError('${e.message}\n\n$message');
      }

      rethrow;
    }
  }
}
