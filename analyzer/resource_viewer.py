import pefile

def get_resources(file_path):
    pe = pefile.PE(file_path)
    resources = []

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            # Get resource type name or ID
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = str(resource_type.struct.Id)

            # Traverse resource directory levels safely
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for lang in resource_id.directory.entries:
                            data_rva = lang.data.struct.OffsetToData
                            size = lang.data.struct.Size
                            resources.append({
                                "Type": name,
                                "Offset": hex(data_rva),
                                "Size": size
                            })

    return resources
