library mysql1.field;

import '../buffer.dart';

class Field {
  final String? catalog;
  final String? db;
  final String? table;
  final String? orgTable;
  final String? name;
  final String? orgName;
  final int? characterSet;
  final int? length;
  final int? type;
  final int? flags;
  final int? decimals;
  final int? defaultValue;

  String get typeString => switch (type) {
    0x00 => 'DECIMAL',
    0x01 => 'TINY',
    0x02 => 'SHORT',
    0x03 => 'LONG',
    0x04 => 'FLOAT',
    0x05 => 'DOUBLE',
    0x06 => 'NULL',
    0x07 => 'TIMESTAMP',
    0x08 => 'LONGLONG',
    0x09 => 'INT24',
    0x0a => 'DATE',
    0x0b => 'TIME',
    0x0c => 'DATETIME',
    0x0d => 'YEAR',
    0x0e => 'NEWDATE',
    0x0f => 'VARCHAR',
    0x10 => 'BIT',
    0xf5 => 'JSON',
    0xf6 => 'NEWDECIMAL',
    0xf7 => 'ENUM',
    0xf8 => 'SET',
    0xf9 => 'TINY_BLOB',
    0xfa => 'MEDIUM_BLOB',
    0xfb => 'LONG_BLOB',
    0xfc => 'BLOB',
    0xfd => 'VAR_STRING',
    0xfe => 'STRING',
    0xff => 'GEOMETRY',
    _ => 'UNKNOWN',
  };

  Field._internal(
      this.catalog,
      this.db,
      this.table,
      this.orgTable,
      this.name,
      this.orgName,
      this.characterSet,
      this.length,
      this.type,
      this.flags,
      this.decimals,
      this.defaultValue);
  Field.forTests(this.type)
      : catalog = null,
        db = null,
        table = null,
        orgTable = null,
        name = null,
        orgName = null,
        characterSet = null,
        length = null,
        flags = null,
        decimals = null,
        defaultValue = null;

  factory Field(Buffer buffer) {
    final catalog = buffer.readLengthCodedString();
    final db = buffer.readLengthCodedString();
    final table = buffer.readLengthCodedString();
    final orgTable = buffer.readLengthCodedString();
    final name = buffer.readLengthCodedString();
    final orgName = buffer.readLengthCodedString();
    buffer.skip(1);
    final characterSet = buffer.readUint16();
    final length = buffer.readUint32();
    final type = buffer.readByte();
    final flags = buffer.readUint16();
    final decimals = buffer.readByte();
    buffer.skip(2);
    int? defaultValue;
    if (buffer.canReadMore()) {
      defaultValue = buffer.readLengthCodedBinary();
    }
    return Field._internal(catalog, db, table, orgTable, name, orgName,
        characterSet, length, type, flags, decimals, defaultValue);
  }

  @override
  String toString() =>
      'Catalog: $catalog, DB: $db, Table: $table, Org Table: $orgTable, '
      'Name: $name, Org Name: $orgName, Character Set: $characterSet, '
      'Length: $length, Type: $type, Flags: $flags, Decimals: $decimals, '
      'Default Value: $defaultValue';
}
