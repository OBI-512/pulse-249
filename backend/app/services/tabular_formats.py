from __future__ import annotations

import csv
from io import BytesIO, StringIO
import json
from pathlib import Path
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile


MAX_IMPORT_BYTES = 15 * 1024 * 1024
MAX_IMPORT_ROWS = 10_000
MAX_CELL_CHARS = 32_000


class TabularFormatError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _safe_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))[:MAX_CELL_CHARS]
    return str(value)[:MAX_CELL_CHARS]


def normalize_rows(rows: Iterable[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    materialized = [dict(row) for row in rows]
    columns: list[str] = []
    seen: set[str] = set()
    for row in materialized:
        for key in row:
            name = str(key)
            if name not in seen:
                seen.add(name)
                columns.append(name)
    return columns, materialized


def parse_csv_bytes(data: bytes) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise TabularFormatError("IMPORT_ENCODING_INVALID", "CSV must use UTF-8 encoding.") from exc
    stream = StringIO(text, newline="")
    try:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise TabularFormatError("IMPORT_HEADER_MISSING", "The import file has no header row.")
        rows: list[dict[str, str]] = []
        for index, row in enumerate(reader, start=1):
            if index > MAX_IMPORT_ROWS:
                raise TabularFormatError("IMPORT_ROW_LIMIT_EXCEEDED", f"Import is limited to {MAX_IMPORT_ROWS} rows.")
            rows.append({str(k).strip(): (v or "").strip()[:MAX_CELL_CHARS] for k, v in row.items() if k is not None})
        return rows
    except csv.Error as exc:
        raise TabularFormatError("IMPORT_CSV_INVALID", "The CSV file could not be parsed.") from exc


def parse_json_bytes(data: bytes) -> list[dict[str, Any]]:
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TabularFormatError("IMPORT_JSON_INVALID", "The JSON file could not be parsed.") from exc
    if isinstance(value, dict) and isinstance(value.get("rows"), list):
        value = value["rows"]
    if not isinstance(value, list):
        raise TabularFormatError("IMPORT_JSON_SHAPE_INVALID", "JSON imports must be an array of row objects or {\"rows\": [...]}.")
    if len(value) > MAX_IMPORT_ROWS:
        raise TabularFormatError("IMPORT_ROW_LIMIT_EXCEEDED", f"Import is limited to {MAX_IMPORT_ROWS} rows.")
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise TabularFormatError("IMPORT_JSON_ROW_INVALID", "Every JSON import row must be an object.")
        rows.append({str(k).strip(): v for k, v in item.items()})
    return rows


def _column_index(cell_reference: str) -> int:
    match = re.match(r"([A-Z]+)", cell_reference.upper())
    if not match:
        return 0
    value = 0
    for char in match.group(1):
        value = value * 26 + (ord(char) - 64)
    return max(0, value - 1)


def parse_xlsx_bytes(data: bytes) -> list[dict[str, str]]:
    try:
        archive = ZipFile(BytesIO(data))
    except Exception as exc:
        raise TabularFormatError("IMPORT_XLSX_INVALID", "The XLSX file could not be opened.") from exc
    with archive:
        names = set(archive.namelist())
        sheet_name = "xl/worksheets/sheet1.xml"
        if sheet_name not in names:
            raise TabularFormatError("IMPORT_XLSX_SHEET_MISSING", "The XLSX file must contain a first worksheet.")
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            for item in root.findall("x:si", ns):
                shared.append("".join(node.text or "" for node in item.findall(".//x:t", ns)))
        root = ET.fromstring(archive.read(sheet_name))
        ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        matrix: list[list[str]] = []
        for row in root.findall(".//x:sheetData/x:row", ns):
            values: list[str] = []
            for cell in row.findall("x:c", ns):
                idx = _column_index(cell.attrib.get("r", "A1"))
                while len(values) <= idx:
                    values.append("")
                cell_type = cell.attrib.get("t")
                if cell_type == "inlineStr":
                    value = "".join(node.text or "" for node in cell.findall(".//x:t", ns))
                else:
                    node = cell.find("x:v", ns)
                    value = node.text if node is not None and node.text is not None else ""
                    if cell_type == "s" and value.isdigit() and int(value) < len(shared):
                        value = shared[int(value)]
                values[idx] = value[:MAX_CELL_CHARS]
            matrix.append(values)
            if len(matrix) > MAX_IMPORT_ROWS + 1:
                raise TabularFormatError("IMPORT_ROW_LIMIT_EXCEEDED", f"Import is limited to {MAX_IMPORT_ROWS} rows.")
    if not matrix:
        raise TabularFormatError("IMPORT_HEADER_MISSING", "The XLSX file has no rows.")
    headers = [value.strip() for value in matrix[0]]
    if not any(headers):
        raise TabularFormatError("IMPORT_HEADER_MISSING", "The XLSX first row must contain column headers.")
    rows: list[dict[str, str]] = []
    for values in matrix[1:]:
        row = {header: (values[index].strip() if index < len(values) else "") for index, header in enumerate(headers) if header}
        if any(value != "" for value in row.values()):
            rows.append(row)
    return rows


@dataclass(frozen=True)
class ParsedTabularData:
    rows: list[dict[str, Any]]
    format: str


def _resolve_import_format(*, filename: str | None, file_format: str | None) -> str:
    if file_format and file_format.strip():
        fmt = file_format.strip().upper().lstrip(".")
    else:
        suffix = Path(filename or "").suffix.lower().lstrip(".")
        fmt = suffix.upper()
    if fmt not in {"CSV", "JSON", "XLSX"}:
        raise TabularFormatError("IMPORT_FORMAT_UNSUPPORTED", "Supported import formats are CSV, XLSX and JSON.")
    return fmt


def parse_tabular_bytes(
    data: bytes, *, filename: str | None = None, file_format: str | None = None
) -> ParsedTabularData:
    if len(data) > MAX_IMPORT_BYTES:
        raise TabularFormatError("IMPORT_FILE_TOO_LARGE", f"Import file exceeds the {MAX_IMPORT_BYTES // (1024*1024)} MB limit.")
    fmt = _resolve_import_format(filename=filename, file_format=file_format)
    if fmt == "CSV":
        rows = parse_csv_bytes(data)
    elif fmt == "JSON":
        rows = parse_json_bytes(data)
    else:
        rows = parse_xlsx_bytes(data)
    return ParsedTabularData(rows=rows, format=fmt.lower())


def _ordered_rows(columns: Sequence[str], rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    names = [str(column) for column in columns]
    return [{name: row.get(name) for name in names} for row in rows]


def write_csv_bytes(columns: Sequence[str], rows: Iterable[dict[str, Any]]) -> bytes:
    names = [str(column) for column in columns]
    materialized = _ordered_rows(names, rows)
    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=names, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in materialized:
        writer.writerow({key: _safe_scalar(row.get(key)) for key in names})
    return stream.getvalue().encode("utf-8-sig")


def write_json_bytes(columns: Sequence[str], rows: Iterable[dict[str, Any]]) -> bytes:
    materialized = _ordered_rows(columns, rows)
    return (json.dumps(materialized, ensure_ascii=False, indent=2, default=str) + "\n").encode("utf-8")


def _xlsx_cell(ref: str, value: Any) -> str:
    text_value = _safe_scalar(value)
    # Inline strings avoid shared-string bookkeeping and keep the writer tiny.
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(text_value)}</t></is></c>'


def _col_name(index: int) -> str:
    result = ""
    value = index + 1
    while value:
        value, rem = divmod(value - 1, 26)
        result = chr(65 + rem) + result
    return result


def write_xlsx_bytes(columns: Sequence[str], rows: Iterable[dict[str, Any]], *, sheet_name: str = "Data") -> bytes:
    names = [str(column) for column in columns]
    materialized = _ordered_rows(names, rows)
    all_rows = [dict(zip(names, names, strict=True)), *materialized] if names else []
    sheet_rows: list[str] = []
    for r_index, row in enumerate(all_rows, start=1):
        cells = "".join(_xlsx_cell(f"{_col_name(c_index)}{r_index}", row.get(column)) for c_index, column in enumerate(names))
        sheet_rows.append(f'<row r="{r_index}">{cells}</row>')
    dimension = f"A1:{_col_name(max(0, len(names)-1))}{max(1, len(all_rows))}" if names else "A1"
    sheet_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="{dimension}"/><sheetData>{''.join(sheet_rows)}</sheetData></worksheet>'''
    workbook_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{escape(sheet_name[:31] or 'Data')}" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'''
    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'''
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook_xml)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return output.getvalue()


def write_tabular_template_bytes(columns: Sequence[str], file_format: str, *, title: str = "FTTW Import Template") -> bytes:
    fmt = file_format.strip().upper()
    names = [str(column) for column in columns]
    if fmt == "CSV":
        return write_csv_bytes(names, [])
    if fmt == "JSON":
        # JSON has no header row, so preserve the template schema explicitly while keeping rows empty.
        return (json.dumps({"columns": names, "rows": []}, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if fmt == "XLSX":
        return write_xlsx_bytes(names, [], sheet_name=title)
    raise TabularFormatError("EXPORT_FORMAT_UNSUPPORTED", "Unsupported template format.")

def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_pdf_bytes(columns: Sequence[str], rows: Iterable[dict[str, Any]], *, title: str = "FTTW Report", max_rows: int = 5000) -> bytes:
    """Write a dependency-free text PDF suitable for operational reports.

    Large report generation is asynchronous; the PDF renderer deliberately
    caps visual rows so pathological exports cannot generate unbounded page
    content. CSV/XLSX/JSON preserve the full result set.
    """
    names = [str(column) for column in columns]
    materialized = _ordered_rows(names, rows)[:max_rows]
    lines = [title, "", " | ".join(names)] if names else [title, "", "No data"]
    for row in materialized:
        lines.append(" | ".join(_safe_scalar(row.get(column)).replace("\n", " ") for column in names))
    if len(materialized) >= max_rows:
        lines.append(f"[PDF display capped at {max_rows} rows; use CSV/XLSX/JSON for complete large datasets]")

    # 55 text lines/page at 10pt Helvetica.
    pages: list[list[str]] = [lines[index:index+55] for index in range(0, len(lines), 55)] or [[title]]
    objects: list[bytes] = []
    # Object 1 catalog, object 2 pages root, object 3 font.
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_ids = [4 + index * 2 for index in range(len(pages))]
    objects.append(f"<< /Type /Pages /Kids [{' '.join(f'{i} 0 R' for i in page_ids)}] /Count {len(page_ids)} >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for page_index, page_lines in enumerate(pages):
        page_id = 4 + page_index * 2
        content_id = page_id + 1
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode())
        commands = ["BT", "/F1 9 Tf", "36 756 Td", "11 TL"]
        for index, line in enumerate(page_lines):
            if index:
                commands.append("T*")
            commands.append(f"({_pdf_escape(line[:110])}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")

    output = BytesIO()
    output.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(f"{index} 0 obj\n".encode())
        output.write(obj)
        output.write(b"\nendobj\n")
    xref = output.tell()
    output.write(f"xref\n0 {len(objects)+1}\n".encode())
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode())
    output.write(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return output.getvalue()


def write_tabular_bytes(
    columns: Sequence[str], rows: Iterable[dict[str, Any]], file_format: str, *, title: str = "FTTW Data"
) -> bytes:
    fmt = file_format.strip().upper()
    if fmt == "CSV":
        return write_csv_bytes(columns, rows)
    if fmt == "JSON":
        return write_json_bytes(columns, rows)
    if fmt == "XLSX":
        return write_xlsx_bytes(columns, rows, sheet_name=title)
    if fmt == "PDF":
        return write_pdf_bytes(columns, rows, title=title)
    raise TabularFormatError("EXPORT_FORMAT_UNSUPPORTED", "Unsupported export format.")
