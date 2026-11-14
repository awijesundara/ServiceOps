"""CSV export cells that a spreadsheet will not run as a formula.

Excel, LibreOffice and Google Sheets evaluate a cell that starts with "=",
"+", "-" or "@" (also after a leading tab or carriage return). Ticket titles,
names and log messages are written by requesters and outside systems, so an
exported value such as =HYPERLINK(...) would execute for the agent who opens
the file. Such text gets a leading apostrophe, which spreadsheets show as
plain text. Numbers stay numbers.
"""
import csv

FORMULA_PREFIXES = ("=", "+", "-", "@")


def safe_cell(value):
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if value[:1] in ("\t", "\r") or stripped.startswith(FORMULA_PREFIXES):
        try:
            float(stripped)  # "-5" or "+3.2" is a number, not a formula
        except ValueError:
            return "'" + value
        return value
    return value


class _SafeWriter:
    def __init__(self, writer):
        self._writer = writer

    def writerow(self, row):
        return self._writer.writerow([safe_cell(value) for value in row])

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def safe_writer(buffer, **options):
    """csv.writer() whose rows pass through safe_cell()."""
    return _SafeWriter(csv.writer(buffer, **options))


def safe_row(row):
    """A DictWriter row with every value passed through safe_cell()."""
    return {key: safe_cell(value) for key, value in row.items()}
