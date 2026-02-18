library mysql1.auth_handler;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';
import 'package:mysql1/src/auth/handshake_handler.dart';

import '../constants.dart';
import '../buffer.dart';
import '../handlers/handler.dart';
import '../mysql_client_error.dart';

List<int> _makeMysqlNativePassword(List<int> scrambler, String password) {
  // SHA1(password)
  final shaPwd = sha1.convert(utf8.encode(password)).bytes;
  // SHA1(SHA1(password))
  final shaShaPwd = sha1.convert(shaPwd).bytes;

  final bytes = List<int>.from(scrambler)..addAll(shaShaPwd);

  // SHA1(scramble, SHA1(SHA1(password)))
  final hash = sha1.convert(bytes).bytes;

  // XOR(SHA1(password), SHA1(scramble, SHA1(SHA1(password))))
  for (var i = 0; i < hash.length; i++) {
    hash[i] ^= shaPwd[i];
  }
  return hash;
}

/// Hash password using MySQL 8+ method (SHA256)
/// XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
List<int> _makeCachingSha2Password(List<int> scrambler, String password) {
  // SHA256(password)
  final shaPwd = sha256.convert(utf8.encode(password)).bytes;
  // SHA256(SHA256(password))
  final shaShaPwd = sha256.convert(shaPwd).bytes;
  // SHA256(SHA256(SHA256(password)))
  final shaShaShaPwd = sha256.convert(shaShaPwd).bytes;
  // SHA256(SHA256(SHA256(password)), scramble)
  final res =
      sha256.convert(List<int>.from(shaShaShaPwd)..addAll(scrambler)).bytes;
  // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
  for (var i = 0; i < res.length; i++) {
    res[i] ^= shaPwd[i];
  }
  return res;
}

class AuthHandler extends Handler {
  static final _publicKeyCache = <String, String>{};

  final String? username;
  final String? password;
  final String? db;
  List<int> _scrambleBuffer;
  List<int> get scrambleBuffer => _scrambleBuffer;
  final int clientFlags;
  final int maxPacketSize;
  final int characterSet;
  AuthPlugin _authPlugin;
  AuthPlugin get authPlugin => _authPlugin;
  final bool _ssl;
  final bool _allowPublicKeyRetrieval;
  final String? _publicKeyCacheKey;
  String? _rsaPublicKey;
  bool _awaitingPublicKey = false;
  Buffer? _pendingRequest;

  AuthHandler(
      this.username,
      this.password,
      this.db,
      List<int> scrambleBuffer,
      this.clientFlags,
      this.maxPacketSize,
      this.characterSet,
      AuthPlugin authPlugin,
      {bool ssl = false,
      bool allowPublicKeyRetrieval = false,
      String? rsaPublicKey,
      String? publicKeyCacheKey})
      : _scrambleBuffer = scrambleBuffer,
        _authPlugin = authPlugin,
        _ssl = ssl,
        _allowPublicKeyRetrieval = allowPublicKeyRetrieval,
        _publicKeyCacheKey = publicKeyCacheKey,
        _rsaPublicKey = rsaPublicKey ??
            (publicKeyCacheKey == null
                ? null
                : _publicKeyCache[publicKeyCacheKey]),
        super(Logger('AuthHandler'));

  List<int> getHash() {
    List<int> hash;
    if (password == null) {
      hash = <int>[];
    } else if (_authPlugin == AuthPlugin.cachingSha2Password) {
      hash = _makeCachingSha2Password(_scrambleBuffer, password!);
    } else {
      hash = _makeMysqlNativePassword(_scrambleBuffer, password!);
    }
    return hash;
  }

  @override
  Buffer createRequest() {
    if (_pendingRequest != null) {
      final buffer = _pendingRequest!;
      _pendingRequest = null;
      return buffer;
    }
    // calculate the mysql password hash
    var hash = getHash();

    var encodedUsername = username == null ? <int>[] : utf8.encode(username!);
    late List<int> encodedDb;
    var encodedAuth = <int>[];

    var size = hash.length + encodedUsername.length + 2 + 32;
    var clientFlags = this.clientFlags;
    if (db != null) {
      encodedDb = utf8.encode(db!);
      size += encodedDb.length + 1;
      clientFlags |= CLIENT_CONNECT_WITH_DB;
    }
    if (clientFlags & CLIENT_PLUGIN_AUTH > 0) {
      encodedAuth = utf8.encode(authPluginToString(_authPlugin));
      size += encodedAuth.length + 1;
    }

    var buffer = Buffer(size);
    buffer.seekWrite(0);
    buffer.writeUint32(clientFlags);
    buffer.writeUint32(maxPacketSize);
    buffer.writeByte(characterSet);
    buffer.fill(23, 0);
    buffer.writeNullTerminatedList(encodedUsername);
    buffer.writeByte(hash.length);
    buffer.writeList(hash);

    if (db != null) {
      buffer.writeNullTerminatedList(encodedDb);
    }
    if (encodedAuth.isNotEmpty) {
      buffer.writeNullTerminatedList(encodedAuth);
    }

    return buffer;
  }

  @override
  HandlerResponse processResponse(Buffer response) {
    final result = checkResponse(response);
    if (result != null) {
      return HandlerResponse(finished: true, result: result);
    }

    if (response[0] == PACKET_EOF) {
      return _handleAuthSwitchRequest(response);
    }

    if (response[0] == 0x01) {
      return _handleAuthMoreData(response);
    }

    return HandlerResponse(finished: true);
  }

  HandlerResponse _handleAuthSwitchRequest(Buffer response) {
    response.seek(0);
    response.readByte();
    final pluginName = response.readNullTerminatedString();
    final newPlugin = authPluginFromString(pluginName);
    final newScramble = _readRemaining(response);
    if (newScramble.isNotEmpty && newScramble.last == 0) {
      newScramble.removeLast();
    }

    _authPlugin = newPlugin;
    if (newScramble.isNotEmpty) {
      _scrambleBuffer = newScramble;
    }

    final hash = getHash();
    _pendingRequest = Buffer(hash.length)..writeList(hash);
    return HandlerResponse(nextHandler: this);
  }

  HandlerResponse _handleAuthMoreData(Buffer response) {
    response.seek(0);
    response.readByte();
    if (_awaitingPublicKey) {
      final keyBytes = _readRemaining(response);
      _rsaPublicKey = utf8
          .decode(keyBytes, allowMalformed: true)
          .replaceAll('\u0000', '')
          .trim();
      final cacheKey = _publicKeyCacheKey;
      if (_rsaPublicKey != null && cacheKey != null) {
        _publicKeyCache[cacheKey] = _rsaPublicKey!;
      }
      _awaitingPublicKey = false;
      return _sendEncryptedPassword();
    }
    if (!response.hasMore) {
      return HandlerResponse.notFinished;
    }

    final marker = response.readByte();
    if (_authPlugin != AuthPlugin.cachingSha2Password) {
      return HandlerResponse.notFinished;
    }

    if (marker == 0x03) {
      return HandlerResponse.notFinished;
    }

    if (marker == 0x04) {
      if (!_ssl) {
        if (_rsaPublicKey == null) {
          if (!_allowPublicKeyRetrieval) {
            throw MySqlClientError(
                'caching_sha2_password requires SSL or a public key when full authentication is needed');
          }
          _pendingRequest = Buffer(1)..writeByte(0x02);
          _awaitingPublicKey = true;
          return HandlerResponse(nextHandler: this);
        }
        print('using cached RSA public key for authentication');
        return _sendEncryptedPassword();
      }
      final passwordBytes = password == null ? <int>[] : utf8.encode(password!);
      final buffer = Buffer(passwordBytes.length + 1);
      buffer.writeList(passwordBytes);
      buffer.writeByte(0);
      _pendingRequest = buffer;
      return HandlerResponse(nextHandler: this);
    }

    return HandlerResponse.notFinished;
  }

  HandlerResponse _sendEncryptedPassword() {
    final publicKey = _rsaPublicKey;
    if (publicKey == null) {
      throw MySqlClientError(
          'caching_sha2_password requires a server public key for full authentication');
    }
    final rsaKey = _parseRsaPublicKey(publicKey);
    final passwordBytes = password == null ? <int>[] : utf8.encode(password!);
    final payload = _xorPasswordWithScramble(passwordBytes, _scrambleBuffer);
    final encrypted = _rsaEncryptOaepSha1(payload, rsaKey);
    _pendingRequest = Buffer(encrypted.length)..writeList(encrypted);
    return HandlerResponse(nextHandler: this);
  }

  List<int> _readRemaining(Buffer response) {
    final remaining = <int>[];
    while (response.hasMore) {
      remaining.add(response.readByte());
    }
    return remaining;
  }

  List<int> _xorPasswordWithScramble(
      List<int> passwordBytes, List<int> scramble) {
    final payload = List<int>.from(passwordBytes)..add(0);
    for (var i = 0; i < payload.length; i++) {
      payload[i] ^= scramble[i % scramble.length];
    }
    return payload;
  }

  _RsaPublicKey _parseRsaPublicKey(String pem) {
    final der = _decodePem(pem);
    final reader = _Asn1Reader(der);
    final outer = reader.readElement(0x30);
    final outerReader = _Asn1Reader(outer);
    if (outerReader.peekByte() == 0x30) {
      outerReader.readElement(0x30);
      final bitString = outerReader.readElement(0x03);
      if (bitString.isEmpty) {
        throw MySqlClientError('Invalid RSA public key');
      }
      final rsaReader =
          _Asn1Reader(Uint8List.fromList(bitString.sublist(1)));
      final rsaSequence = rsaReader.readElement(0x30);
      return _parseRsaPublicKeyElements(rsaSequence);
    }
    return _parseRsaPublicKeyElements(outer);
  }

  _RsaPublicKey _parseRsaPublicKeyElements(Uint8List content) {
    final reader = _Asn1Reader(content);
    final modulus = _readInteger(reader);
    final exponent = _readInteger(reader);
    return _RsaPublicKey(modulus, exponent);
  }

  BigInt _readInteger(_Asn1Reader reader) {
    var bytes = reader.readElement(0x02);
    var start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    bytes = bytes.sublist(start);
    return _bigIntFromBytes(bytes);
  }

  Uint8List _decodePem(String pem) {
    final lines = pem.split(RegExp(r'\r?\n'));
    final buffer = StringBuffer();
    for (final line in lines) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) {
        continue;
      }
      if (trimmed.startsWith('-----')) {
        continue;
      }
      buffer.write(trimmed);
    }
    return Uint8List.fromList(base64.decode(buffer.toString()));
  }

  List<int> _rsaEncryptOaepSha1(List<int> message, _RsaPublicKey key) {
    final modulusLength = (key.modulus.bitLength + 7) ~/ 8;
    const hashLength = 20;
    final maxMessageLength = modulusLength - (2 * hashLength) - 2;
    if (message.length > maxMessageLength) {
      throw MySqlClientError('RSA public key is too short');
    }
    final lHash = sha1.convert(const <int>[]).bytes;
    final psLength = modulusLength - message.length - (2 * hashLength) - 2;
    final db = Uint8List(lHash.length + psLength + 1 + message.length);
    var offset = 0;
    db.setRange(offset, offset + lHash.length, lHash);
    offset += lHash.length;
    offset += psLength;
    db[offset] = 1;
    offset++;
    db.setRange(offset, offset + message.length, message);

    final random = Random.secure();
    final seed =
        Uint8List.fromList(List<int>.generate(hashLength, (_) => random.nextInt(256)));
    final dbMask = _mgf1(seed, db.length);
    for (var i = 0; i < db.length; i++) {
      db[i] ^= dbMask[i];
    }
    final seedMask = _mgf1(db, hashLength);
    for (var i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i];
    }

    final encoded = Uint8List(modulusLength);
    encoded[0] = 0;
    encoded.setRange(1, 1 + seed.length, seed);
    encoded.setRange(1 + seed.length, modulusLength, db);
    final value = _bigIntFromBytes(encoded);
    final encrypted = value.modPow(key.exponent, key.modulus);
    return _bigIntToBytes(encrypted, modulusLength);
  }

  Uint8List _mgf1(List<int> seed, int length) {
    final output = Uint8List(length);
    var offset = 0;
    var counter = 0;
    while (offset < length) {
      final c = Uint8List(4);
      c[0] = (counter >> 24) & 0xff;
      c[1] = (counter >> 16) & 0xff;
      c[2] = (counter >> 8) & 0xff;
      c[3] = counter & 0xff;
      final block = sha1.convert([...seed, ...c]).bytes;
      final remaining = length - offset;
      final copyLength = remaining < block.length ? remaining : block.length;
      output.setRange(offset, offset + copyLength, block);
      offset += copyLength;
      counter++;
    }
    return output;
  }

  BigInt _bigIntFromBytes(Uint8List bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }

  List<int> _bigIntToBytes(BigInt value, int length) {
    final result = Uint8List(length);
    var current = value;
    for (var i = length - 1; i >= 0; i--) {
      result[i] = (current & BigInt.from(0xff)).toInt();
      current = current >> 8;
    }
    return result;
  }
}

class _Asn1Reader {
  final Uint8List _data;
  int _offset = 0;

  _Asn1Reader(this._data);

  int peekByte() => _data[_offset];

  int readByte() => _data[_offset++];

  Uint8List readBytes(int length) {
    final bytes = _data.sublist(_offset, _offset + length);
    _offset += length;
    return bytes;
  }

  int readLength() {
    final length = readByte();
    if (length < 0x80) {
      return length;
    }
    final count = length & 0x7f;
    var value = 0;
    for (var i = 0; i < count; i++) {
      value = (value << 8) | readByte();
    }
    return value;
  }

  Uint8List readElement(int expectedTag) {
    final tag = readByte();
    if (tag != expectedTag) {
      throw MySqlClientError('Unexpected ASN.1 tag: $tag');
    }
    final length = readLength();
    return readBytes(length);
  }
}

class _RsaPublicKey {
  final BigInt modulus;
  final BigInt exponent;

  _RsaPublicKey(this.modulus, this.exponent);
}
