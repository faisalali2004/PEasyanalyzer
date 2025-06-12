import pefile

def get_import_table(file_path):
    pe = pefile.PE(file_path)
    imports = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            for imp in entry.imports:
                imports.append({
                    "DLL": dll,
                    "Function": imp.name.decode() if imp.name else "Ordinal({})".format(imp.ordinal)
                })

    return imports
