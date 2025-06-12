import pefile
import os
import datetime


def extract_metadata(file_path):
    try:
        pe = pefile.PE(file_path)

        timestamp = datetime.datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')

        subsystem_map = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI",
            5: "OS/2 CUI",
            7: "POSIX CUI",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "XBOX",
            16: "Windows Boot Application"
        }

        dll_characteristics = []
        flags = pe.OPTIONAL_HEADER.DllCharacteristics
        if flags & 0x0020: dll_characteristics.append("High Entropy VA")
        if flags & 0x0040: dll_characteristics.append("Dynamic Base")
        if flags & 0x0080: dll_characteristics.append("Force Integrity")
        if flags & 0x0100: dll_characteristics.append("NX Compatible")
        if flags & 0x0200: dll_characteristics.append("No Isolation")
        if flags & 0x0400: dll_characteristics.append("No SEH")
        if flags & 0x0800: dll_characteristics.append("No Bind")
        if flags & 0x1000: dll_characteristics.append("AppContainer")
        if flags & 0x2000: dll_characteristics.append("WDM Driver")
        if flags & 0x8000: dll_characteristics.append("Guard CF")

        info = {
            "File": os.path.basename(file_path),
            "Machine Type": hex(pe.FILE_HEADER.Machine),
            "Number of Sections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": timestamp,
            "Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "Subsystem": subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
            "Compiler Magic": hex(pe.OPTIONAL_HEADER.Magic),
            "DLL Characteristics": dll_characteristics,
            "Size of Code": pe.OPTIONAL_HEADER.SizeOfCode,
            "Size of Initialized Data": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "Size of Uninitialized Data": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            "Executable Type": "DLL" if pe.is_dll() else "EXE"
        }

        return info

    except Exception as e:
        return {"Error": str(e)}