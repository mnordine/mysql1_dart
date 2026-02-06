library mysql1.auth_handler;

import 'dart:convert';

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
  // SHA256(SHA256(SHA256(password)), scramble)
  final res = sha256.convert(List.from(shaShaPwd)..addAll(scrambler)).bytes;
  // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
  for (var i = 0; i < res.length; i++) {
    res[i] ^= shaPwd[i];
  }
  return res;
}

class AuthHandler extends Handler {
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
      {bool ssl = false})
      : _scrambleBuffer = scrambleBuffer,
        _authPlugin = authPlugin,
        _ssl = ssl,
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
        throw MySqlClientError(
            'caching_sha2_password requires SSL or a public key when full authentication is needed');
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

  List<int> _readRemaining(Buffer response) {
    final remaining = <int>[];
    while (response.hasMore) {
      remaining.add(response.readByte());
    }
    return remaining;
  }
}
