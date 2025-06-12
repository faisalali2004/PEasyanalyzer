import pefile

def get_pe_sections(file_path):
    """
    Extract detailed information about each section in a PE file.

    :param file_path: Path to the PE file.
    :return: List of dictionaries containing section information.
    """
    sections = []
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            section_info = {
                "Name": section.Name.decode(errors='ignore').rstrip('\x00'),
                "VirtualSize": section.Misc_VirtualSize,
                "VirtualAddress": hex(section.VirtualAddress),
                "SizeOfRawData": section.SizeOfRawData,
                "PointerToRawData": hex(section.PointerToRawData),
                "Entropy": round(section.get_entropy(), 2),
                "Characteristics": hex(section.Characteristics),
                "Readable": bool(section.Characteristics & 0x40000000),
                "Writable": bool(section.Characteristics & 0x80000000),
                "Executable": bool(section.Characteristics & 0x20000000),
            }
            sections.append(section_info)
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
    return sections
