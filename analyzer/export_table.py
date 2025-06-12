import pefile

def get_export_table(file_path):
    pe = pefile.PE(file_path)
    exports = []

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "Address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                "Name": exp.name.decode() if exp.name else "N/A",
                "Ordinal": exp.ordinal
            })

    return exports
