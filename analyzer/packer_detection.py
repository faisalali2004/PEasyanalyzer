import pefile

# Common section names associated with known packers
KNOWN_PACKERS = {
    "UPX": ["UPX0", "UPX1", "UPX2"],
    "ASPack": [".aspack"],
    "FSG": [".fsg"],
    "MEW": [".mew"],
    "Petite": [".petite"],
    "Themida": [".themida"],
    "PECompact": [".pec", ".pec1", ".pec2"],
    "MPRESS": [".MPRESS1", ".MPRESS2"],
    "NSPack": [".nsp0", ".nsp1"],
    "UPack": [".upx", ".packed", ".boom"],
}

def detect_packer(file_path):
    try:
        pe = pefile.PE(file_path)
        detected_packers = []

        section_names = [s.Name.decode(errors='ignore').rstrip('\x00') for s in pe.sections]

        for packer, patterns in KNOWN_PACKERS.items():
            if any(name in section_names for name in patterns):
                detected_packers.append(packer)

        # Heuristic: very few sections with high entropy
        if len(pe.sections) <= 3:
            high_entropy_sections = [s for s in pe.sections if s.get_entropy() > 6.5]
            if len(high_entropy_sections) >= 1:
                detected_packers.append("Possible Custom Packer")

        return detected_packers if detected_packers else ["None detected"]

    except Exception as e:
        return [f"Error during detection: {str(e)}"]
