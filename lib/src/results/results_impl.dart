library mysql1.results_impl;

import 'dart:async';
import 'dart:collection';

import 'field.dart';
import 'row.dart';

class ResultsStream extends StreamView<Row> {
  final int insertId;
  final int affectedRows;

  final List<Field> fields;

  factory ResultsStream(int insertId, int affectedRows, List<Field> fields,
      {Stream<Row> stream}) {
    if (stream != null) {
      var newStream = stream.transform(
          StreamTransformer.fromHandlers(handleDone: (EventSink<Row> sink) {
        sink.close();
      }));
      return ResultsStream._fromStream(
          insertId, affectedRows, fields, newStream);
    } else {
      var newStream = Stream.fromIterable(<Row>[]);
      return ResultsStream._fromStream(
          insertId, affectedRows, fields, newStream);
    }
  }

  ResultsStream._fromStream(
      this.insertId, this.affectedRows, List<Field> fields, Stream<Row> stream)
      : fields = UnmodifiableListView(fields),
        super(stream);

  /// Takes a _ResultsImpl and destreams it. That is, it listens to the stream, collecting
  /// all the rows into a list until the stream has finished. It then returns a new
  /// _ResultsImpl which wraps that list of rows.
  static Future<ResultsStream> destream(ResultsStream results) async {
    var rows = await results.toList();
    var newStream = Stream<Row>.fromIterable(rows);
    return ResultsStream._fromStream(
        results.insertId, results.affectedRows, results.fields, newStream);
  }
}
