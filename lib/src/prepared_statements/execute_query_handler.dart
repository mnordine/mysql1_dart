// ignore_for_file: argument_type_not_assignable, return_of_invalid_type, strong_mode_implicit_dynamic_return, strong_mode_implicit_dynamic_variable, invalid_assignment, strong_mode_implicit_dynamic_parameter, strong_mode_implicit_dynamic_type

library mysql1.execute_query_handler;

import 'dart:async';
import 'dart:convert';

import 'package:logging/logging.dart';
import 'package:mysql1/src/mysql_client_error.dart';

import '../constants.dart';
import '../buffer.dart';
import '../handlers/handler.dart';
import '../handlers/ok_packet.dart';

import 'binary_data_packet.dart';
import 'prepared_query.dart';

import '../results/results_impl.dart';
import '../results/field.dart';
import '../results/row.dart';
import '../query/result_set_header_packet.dart';
import '../blob.dart';

class ExecuteQueryHandler extends Handler {
  static const int STATE_HEADER_PACKET = 0;
  static const int STATE_FIELD_PACKETS = 1;
  static const int STATE_ROW_PACKETS = 2;

  int _state = STATE_HEADER_PACKET;

  List<Field> fieldPackets;
//  Map<Symbol, int> _fieldIndex;
  StreamController<ResultRow>? _streamController;

  final PreparedQuery? _preparedQuery;
  final List<Object?> _values;
  List<Object?>? preparedValues;
  late OkPacket _okPacket;
  final bool _executed;
  bool _cancelled = false;

  ExecuteQueryHandler(this._preparedQuery, this._executed, this._values)
      : fieldPackets = <Field>[],
        super(Logger('ExecuteQueryHandler'));

  @override
  Buffer createRequest() {
    var length = 0;
    var types = List<int>.filled(_values.length * 2, 0);

    var nullMap = createNullMap();
    preparedValues = List.filled(_values.length, null);
    for (var i = 0; i < _values.length; i++) {
      final value = _values[i];
      var parameterType = _getType(value);
      types[i * 2] = parameterType;
      types[i * 2 + 1] = 0;
      preparedValues![i] = prepareValue(value);
      length += measureValue(value, preparedValues![i]);
    }

    var buffer = writeValuesToBuffer(nullMap, length, types);
    return buffer;
  }

  Object? prepareValue(Object? value) => switch (value) {
    null => null,
    int x => _prepareInt(x),
    double x => _prepareDouble(x),
    DateTime x => _prepareDateTime(x),
    bool x => _prepareBool(x),
    List<int> xs => _prepareList(xs),
    Blob blob => _prepareBlob(blob),
    _ => _prepareString(value),
  };

  int measureValue(Object? value, Object? preparedValue) => switch ((value, preparedValue)) {
    (null, _) => 0,
    (int a, _) => _measureInt(a, preparedValue),
    (double a, List<Object> xs) => _measureDouble(a, xs),
    (DateTime _, _) => _measureDateTime(value, preparedValue),
    (bool _, _) => _measureBool(value, preparedValue),
    (List<int> xs, Object b) => _measureList(xs, b),
    (Blob blob, List<Object> xs) => _measureBlob(blob, xs),
    (String a, List<Object> xs) => _measureString(a, xs),
    _ => throw ArgumentError('cannot measure $value'),
  };

  int _getType(Object? value) => switch (value) {
    null => FIELD_TYPE_NULL,
    int _ => FIELD_TYPE_LONGLONG,
    DateTime _ => FIELD_TYPE_DATETIME,
    bool _ => FIELD_TYPE_TINY,
    List<int> _ || Blob _ => FIELD_TYPE_BLOB,
    _ => FIELD_TYPE_VARCHAR,
  };

  void _writeValue(Object? value, Object? preparedValue, Buffer buffer) => switch ((value, preparedValue)) {
    (null, _) => () {},
    (int x, _) => _writeInt(x, preparedValue, buffer),
    (double x, List<int> xs) => _writeDouble(x, xs, buffer),
    (DateTime x, _) => _writeDateTime(x, preparedValue, buffer),
    (bool x, _) => _writeBool(x, preparedValue, buffer),
    (List<int> xs, _) => _writeList(xs, preparedValue, buffer),
    (Blob blob, List<int> xs) => _writeBlob(blob, xs, buffer),
    (String s, List<int> xs) => _writeString(s, xs, buffer),
    _ => throw ArgumentError('cannot write $value'),
  };

  int _prepareInt(int value) {
    return value;
  }

  int _measureInt(value, preparedValue) {
    return 8;
  }

  void _writeInt(int value, Object? preparedValue, Buffer buffer) {
//          if (value < 128 && value > -127) {
//            log.fine("TINYINT: value");
//            types.add(FIELD_TYPE_TINY);
//            types.add(0);
//            values.add(value & 0xFF);
//          } else {
    log.fine('LONG: $value');
    buffer.writeByte(value >> 0x00 & 0xFF);
    buffer.writeByte(value >> 0x08 & 0xFF);
    buffer.writeByte(value >> 0x10 & 0xFF);
    buffer.writeByte(value >> 0x18 & 0xFF);
    buffer.writeByte(value >> 0x20 & 0xFF);
    buffer.writeByte(value >> 0x28 & 0xFF);
    buffer.writeByte(value >> 0x30 & 0xFF);
    buffer.writeByte(value >> 0x38 & 0xFF);
//          }
  }

  List<int> _prepareDouble(Object value) {
    return utf8.encode(value.toString());
  }

  int _measureDouble(double value, List<Object> preparedValue) {
    return Buffer.measureLengthCodedBinary(preparedValue.length) +
        preparedValue.length;
  }

  void _writeDouble(Object value, List<int> preparedValue, Buffer buffer) {
    log.fine('DOUBLE: $value');

    buffer.writeLengthCodedBinary(preparedValue.length);
    buffer.writeList(preparedValue);

    // TODO: if you send a double value for a decimal field, it doesn't like it
//          types.add(FIELD_TYPE_FLOAT);
//          types.add(0);
//          values.addAll(doubleToList(value));
  }

  DateTime _prepareDateTime(DateTime value) {
    // The driver requires DateTime values to be in UTC and will always give back a UTC DateTime.
    if (!value.isUtc) {
      throw MySqlClientError('DateTime value is not in UTC');
    }
    return value;
  }

  int _measureDateTime(value, preparedValue) {
    return 8;
  }

  void _writeDateTime(DateTime value, Object? preparedValue, Buffer buffer) {
    // TODO remove Date eventually
    log.fine('DATE: $value');
    buffer.writeByte(7);
    buffer.writeByte(value.year >> 0x00 & 0xFF);
    buffer.writeByte(value.year >> 0x08 & 0xFF);
    buffer.writeByte(value.month);
    buffer.writeByte(value.day);
    buffer.writeByte(value.hour);
    buffer.writeByte(value.minute);
    buffer.writeByte(value.second);
  }

  Object _prepareBool(Object value) {
    return value;
  }

  int _measureBool(value, preparedValue) {
    return 1;
  }

  void _writeBool(bool value, Object? preparedValue, Buffer buffer) {
    log.fine('BOOL: $value');
    buffer.writeByte(value ? 1 : 0);
  }

  Object _prepareList(Object value) {
    return value;
  }

  int _measureList(List<Object> value, Object preparedValue) {
    return Buffer.measureLengthCodedBinary(value.length) + value.length;
  }

  void _writeList(List<int> value, Object? preparedValue, Buffer buffer) {
    log.fine('LIST: $value');
    buffer.writeLengthCodedBinary(value.length);
    buffer.writeList(value);
  }

  List<int> _prepareBlob(Blob value) {
    return value.toBytes();
  }

  int _measureBlob(Blob value, List<Object> preparedValue) {
    return Buffer.measureLengthCodedBinary(preparedValue.length) + preparedValue.length;
  }

  void _writeBlob(Object value, List<int> preparedValue, Buffer buffer) {
    log.fine('BLOB: $value');
    buffer.writeLengthCodedBinary(preparedValue.length);
    buffer.writeList(preparedValue);
  }

  List<int> _prepareString(Object value) {
    return utf8.encode(value.toString());
  }

  int _measureString(String value, List<Object> preparedValue) {
    return Buffer.measureLengthCodedBinary(preparedValue.length) + preparedValue.length;
  }

  void _writeString(String value, List<int> preparedValue, Buffer buffer) {
    log.fine('STRING: $value');
    buffer.writeLengthCodedBinary(preparedValue.length);
    buffer.writeList(preparedValue);
  }

  List<int> createNullMap() {
    var bytes = ((_values.length + 7) / 8).floor();
    var nullMap = List<int>.filled(bytes, 0);
    var byte = 0;
    var bit = 0;
    for (var i = 0; i < _values.length; i++) {
      if (_values[i] == null) {
        nullMap[byte] = nullMap[byte] + (1 << bit);
      }
      bit++;
      if (bit > 7) {
        bit = 0;
        byte++;
      }
    }

    return nullMap;
  }

  Buffer writeValuesToBuffer(List<int> nullMap, int length, List<int> types) {
    var buffer = Buffer(10 + nullMap.length + 1 + types.length + length);
    buffer.writeByte(COM_STMT_EXECUTE);
    buffer.writeUint32(_preparedQuery!.statementHandlerId);
    buffer.writeByte(0);
    buffer.writeUint32(1);
    buffer.writeList(nullMap);
    if (!_executed) {
      buffer.writeByte(1);
      buffer.writeList(types);
      for (var i = 0; i < _values.length; i++) {
        _writeValue(_values[i], preparedValues![i], buffer);
      }
    } else {
      buffer.writeByte(0);
    }
    return buffer;
  }

  @override
  HandlerResponse processResponse(Buffer response) {
    Object? packet;
    if (_cancelled) {
      unawaited(_streamController?.close());
      return HandlerResponse(finished: true);
    }
    if (_state == STATE_HEADER_PACKET) {
      packet = checkResponse(response);
    }
    if (packet == null) {
      if (response[0] == PACKET_EOF) {
        log.fine('Got an EOF');
        if (_state == STATE_FIELD_PACKETS) {
          return _handleEndOfFields();
        } else if (_state == STATE_ROW_PACKETS) {
          return _handleEndOfRows();
        }
      } else {
        switch (_state) {
          case STATE_HEADER_PACKET: _handleHeaderPacket(response);
          case STATE_FIELD_PACKETS: _handleFieldPacket(response);
          case STATE_ROW_PACKETS: _handleRowPacket(response);
        }
      }
    } else if (packet is OkPacket) {
      _okPacket = packet;
      if ((packet.serverStatus & SERVER_MORE_RESULTS_EXISTS) == 0) {
        return HandlerResponse(
            finished: true,
            result: ResultsStream(
                _okPacket.insertId, _okPacket.affectedRows, null));
      }
    }
    return HandlerResponse.notFinished;
  }

  HandlerResponse _handleEndOfFields() {
    _state = STATE_ROW_PACKETS;
    _streamController = StreamController<ResultRow>();
    _streamController!.onCancel = () {
      _cancelled = true;
    };
    return HandlerResponse(
        result: ResultsStream(null, null, fieldPackets,
            stream: _streamController?.stream));
  }

  HandlerResponse _handleEndOfRows() {
    _streamController?.close();
    return HandlerResponse(finished: true);
  }

  void _handleHeaderPacket(Buffer response) {
    log.fine('Got a header packet');
    final resultSetHeaderPacket = ResultSetHeaderPacket(response);
    log.fine(resultSetHeaderPacket.toString());
    _state = STATE_FIELD_PACKETS;
  }

  void _handleFieldPacket(Buffer response) {
    log.fine('Got a field packet');
    var fieldPacket = Field(response);
    log.fine(fieldPacket.toString());
    fieldPackets.add(fieldPacket);
  }

  void _handleRowPacket(Buffer response) {
    log.fine('Got a row packet');
    var dataPacket = BinaryDataPacket(response, fieldPackets);
    log.fine(dataPacket.toString());
    _streamController?.add(dataPacket);
  }
}
