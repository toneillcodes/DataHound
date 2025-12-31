import pandas as pd
import logging
import hashlib
import pefile
import json
import uuid
import os

def get_pe_metadata(config):
    """
    Extracts basic file info, hashes, and version metadata.
    Returns a flat dictionary ready for a DataFrame.
    """
    # validation, this should have been done already, but we won't get far without the source_path
    source_path = config.get('source_path')
    if not source_path or not os.path.exists(source_path):
        return None
    
    # this isn't used currently but might be helpful    
    correlation_id = config.get('correlation_id')

    try:
        pe = pefile.PE(source_path)

        # calculate hashes and read magic bytes
        with open(source_path, 'rb') as f:
            file_data = f.read()
            md5 = hashlib.md5(file_data).hexdigest()
            sha1 = hashlib.sha1(file_data).hexdigest()
            sha256 = hashlib.sha256(file_data).hexdigest()        
            raw_magic = file_data[:2] 
            magic_hex = raw_magic.hex().upper()
            magic_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw_magic])

        # composite header
        metadata = {
            "correlation_id": correlation_id,
            "filename": os.path.basename(source_path),
            "size_bytes": os.path.getsize(source_path),
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "magic_hex": magic_hex,
            "magic_ascii": magic_ascii,
            "imphash": pe.get_imphash(), # Fingerprint of the IAT
            "exphash": pe.get_exphash(), # Fingerprint of the EAT
            "machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"),
            "compile_time": pd.to_datetime(pe.FILE_HEADER.TimeDateStamp, unit='s'),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")
        }

        # Extract Version Information (Company, Original Filename, etc.)
        if hasattr(pe, 'FileInfo'):
            # pe.FileInfo is a list of lists (usually containing StringFileInfo or VarFileInfo)
            for file_info_list in pe.FileInfo:
                for item in file_info_list:
                    # Now we check if this specific object has the 'StringTable' we want
                    if hasattr(item, 'StringTable'):
                        for st in item.StringTable:
                            for key, value in st.entries.items():
                                # key and value are often bytes, so we decode them
                                k = key.decode('utf-8', errors='ignore')
                                v = value.decode('utf-8', errors='ignore')
                                metadata[f"version_{k}"] = v

        return pd.DataFrame([metadata]) # Returns as a single-row DataFrame
        
    except Exception as e:
        logging.error(f"Metadata extraction failed: {str(e)}")
        return None 
    
def get_sections_dataframe(config):
    item_name = config.get('item_name')
    file_path = config.get('source_path')
    # validation, this should have been done already, but we won't get far without the source_path
    if not file_path or not os.path.exists(file_path):
        return None

    # this isn't used currently but might be helpful
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))

    try:
        pe = pefile.PE(file_path)
        
        # get the single-row metadata DataFrame to correlate sections with exectuable
        df_metadata = get_pe_metadata(config)

        if df_metadata is None:
            logging.error(f"Failed to collect PE metadata while compiling Sections DF. Stopping Sections processing for item: {item_name}.")
            return False

        rows = []
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            rows.append({
                "correlation_id": correlation_id, 
                "Section_Name": section_name,
                "Virtual_Address": hex(section.VirtualAddress),
                "Virtual_Size": hex(section.Misc_VirtualSize),
                "Raw_Size": section.SizeOfRawData,
                "Entropy": section.get_entropy(),
                "Characteristics": hex(section.Characteristics)
            })

        # convert the sections list to a DataFrame
        df_sections = pd.DataFrame(rows)

        # example using an 'inner' join on correlation_id
        '''
        if df_metadata is not None and not df_metadata.empty:
            merged_df = pd.merge(df_sections, df_metadata, on="correlation_id", how="inner")
            return merged_df
        '''
        # This ignores all column values and just joins everything to everything
        merged_df = pd.merge(df_sections, df_metadata, how="cross")
        #print(f"merged_df: {merged_df}")
        return merged_df

    except Exception as e:
        print(f"Error parsing sections for {file_path}: {e}")
        return None

def get_directory_section_info(file_path, directory_key):
    """
    Generic helper to find the section name and VA for a PE directory entry.
    directory_key: e.g., 'IMAGE_DIRECTORY_ENTRY_EXPORT' or 'IMAGE_DIRECTORY_ENTRY_IAT'
    """
    if not file_path or not os.path.exists(file_path):
        return None    
    try:
        pe = pefile.PE(file_path)
        
        # get the directory entry index and its data
        dir_index = pefile.DIRECTORY_ENTRY[directory_key]
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
        
        if data_dir.VirtualAddress == 0:
            logging.debug(f"No {directory_key} found.")
            return None

        # find the section containing the VA
        section = pe.get_section_by_rva(data_dir.VirtualAddress)
        
        if section:
            section_name = section.Name.decode('utf-8').strip('\x00')
            return section_name, data_dir.VirtualAddress

        return None

    except Exception as e:
        logging.error(f"Error parsing {file_path}: {e}")
        return None    

def find_eat_section(file_path):
    # validation, this should have been done already
    if not os.path.exists(file_path):
        return None
    
    try:
        pe = pefile.PE(file_path)
        
        # Get the Export Data Directory (Index 0)
        # IMAGE_DIRECTORY_ENTRY_EXPORT = 0
        eat_entry = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        eat_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[eat_entry]
        
        eat_va = eat_dir.VirtualAddress
        eat_size = eat_dir.Size

        # todo: debug output        
        #print(f"EAT Virtual Address: {hex(eat_va)}")
        #print(f"EAT Size: {hex(eat_size)}\n")

        if eat_va == 0:
            logging.debug("No Export directory found (common in .exe files).")
            return None

        # Iterate through sections to find which one contains the eat_va
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            section_start = section.VirtualAddress
            section_end = section.VirtualAddress + section.Misc_VirtualSize
            
            # Check if the Export Table starts within this section
            if section_start <= eat_va < section_end:
                return section_name, eat_va

        return None

    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def find_iat_section(file_path):
    # validation, this should have been done already
    if not os.path.exists(file_path):
        return None
    
    try:
        pe = pefile.PE(file_path)
        
        # Get the IAT Data Directory (Index 12)
        # IMAGE_DIRECTORY_ENTRY_IAT = 12
        iat_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']]
        
        iat_va = iat_dir.VirtualAddress
        # does this matter? i don't think so
        iat_size = iat_dir.Size

        if iat_va == 0:
            logging.debug("No IAT directory found (common in some DLLs or packed files).")
            return None

        # todo: debug output        
        #print(f"IAT Virtual Address: {hex(iat_va)}")
        #print(f"IAT Size: {hex(iat_size)}\n")

        # iterate through pe.sections to find where the the IAT lives based on the VA
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            section_start = section.VirtualAddress
            section_end = section.VirtualAddress + section.Misc_VirtualSize
            
            # check if the IAT starts within this section
            if section_start <= iat_va < section_end:
                return section_name, iat_va

        return None

    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def get_iat_dataframe(config):
    """
    Parses the IAT using the provided config.
    Extracts correlation_id and source_path from the config dict.
    """
    # validation, this should have been done already, but we won't get far without the source_path
    file_path = config.get('source_path')    
    if not os.path.exists(file_path):
        return None
    
    # this isn't used currently but might be helpful
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))

    try:
        # initialize df
        df_iat = None
        # load pe
        pe = pefile.PE(file_path)
        rows = []

        # todo: this should be removed, enrichment happens at the process step
        df_metadata = get_pe_metadata(config)

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # Use errors='ignore' to prevent crashes on obfuscated names
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                
                for imp in entry.imports:
                    # Resolve name or ordinal
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"ordinal_{imp.ordinal}"
                    
                    # build composite data object
                    rows.append({
                        "correlation_id": correlation_id, # this isn't used currently but might be helpful
                        "DLL": dll_name,
                        "Function": func_name,
                        "IAT_Address": hex(imp.address),
                        "TimeDateStamp": entry.struct.TimeDateStamp
                    })

        df_iat = pd.DataFrame(rows)

        # Use an 'inner' join on correlation_id to broadcast metadata to all sections
        '''
        if df_metadata is not None and not df_metadata.empty:
            merged_df = pd.merge(df_sections, df_metadata, on="correlation_id", how="inner")
            return merged_df
        '''
        # This ignores all column values and just joins everything to everything
        merged_df = pd.merge(df_iat, df_metadata, how="cross")
        #print(f"merged_df: {merged_df}")
        return merged_df

    except Exception as e:
        print(f"Error parsing IAT for {file_path}: {e}")
        return None

def get_iat_with_malapi_dataframe(config):
    """
    Parses the IAT, cross-references MalAPI categories, and merges 
    with file metadata using a cross join.
    """
    # validation, this should have been done already, but we won't get far without the source_path
    file_path = config.get('source_path')    
    if not os.path.exists(file_path):
        return None

    # this isn't used currently but might be helpful
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    
    # retrieve PE metadata
    df_metadata = get_pe_metadata(config)

    if df_metadata is None:
        logging.error(f"Failed to collect PE metadata while compiling IAT DF. Stopping IAT collection.")
        return False

    # todo: consider a better appproach for MalAPI mapping 
    #       (move to an external JSON/Dict? should not be baked into code)
    MALAPI_MAP = {
        "VirtualAlloc": {"category": "Injection", "risk": "High"},
        "WriteProcessMemory": {"category": "Injection", "risk": "High"},
        "CreateRemoteThread": {"category": "Injection", "risk": "High"},
        "IsDebuggerPresent": {"category": "Anti-Debugging", "risk": "Medium"},
        "CheckRemoteDebuggerPresent": {"category": "Anti-Debugging", "risk": "Medium"},
        "SetWindowsHookEx": {"category": "Spyware", "risk": "High"},
        "URLDownloadToFile": {"category": "Downloader", "risk": "High"}
    }

    try:
        pe = pefile.PE(file_path)
        
        # logic for IAT Section anomalies
        iat_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']]
        iat_vaddr = iat_entry.VirtualAddress
        iat_section = pe.get_section_by_rva(iat_vaddr)
        
        is_unmapped = (iat_vaddr > 0 and iat_section is None)
        parent_section = iat_section.Name.decode('utf-8', errors='ignore').strip('\x00') if iat_section else "UNMAPPED"

        rows = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ord_{imp.ordinal}"
                    
                    # Cross-reference with MalAPI
                    mal_info = MALAPI_MAP.get(func_name, {"category": "Standard", "risk": "None"})
                    filehash = df_metadata['sha256'].iloc[0]

                    rows.append({
                        "correlation_id": correlation_id,
                        "DLL": dll_name,
                        "Function": func_name,
                        "IAT_ID": f"IAT-{filehash}",
                        "IAT_Address": hex(imp.address),
                        "IAT_Parent_Section": parent_section,
                        "Is_Anomalous_Location": is_unmapped,
                        "MalAPI_Category": mal_info['category'],
                        "MalAPI_Risk": mal_info['risk']
                    })
        
        # convert to a dataframe
        df_iat = pd.DataFrame(rows)
        merged_df = pd.merge(df_iat, df_metadata, how="cross")
        return merged_df
        
    except Exception as e:
        print(f"Error parsing IAT/MalAPI for {file_path}: {e}")
        return None

def get_exports_dataframe(config):
    """
    Parses the Export Directory using the provided config.
    Extracts correlation_id and source_path from the config dict.
    """
    # validation, this should have been done already, but we won't get far without the source_path
    file_path = config.get('source_path')
    if not file_path:
        return None
        
    # this isn't used currently but might be helpful
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))

    try:
        pe = pefile.PE(file_path)
        rows = []

        # retrieve PE metadata
        df_metadata = get_pe_metadata(config)
        if df_metadata is None:
            logging.error(f"Failed to collect PE metadata while compiling IAT DF. Stopping IAT collection.")
            return False

        # Check if the PE has an Export Directory
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                # Resolve the name (exports can be named or ordinal-only)
                if exp.name:
                    func_name = exp.name.decode('utf-8', errors='ignore')
                else:
                    func_name = f"ordinal_{exp.ordinal}"

                # composite EAT entry data
                rows.append({
                    "correlation_id": correlation_id, # The join key
                    "Export_Name": func_name,
                    "Ordinal": exp.ordinal,
                    "Address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    "Internal_RVA": hex(exp.address),
                    "Forwarder": exp.forwarder.decode('utf-8', errors='ignore') if exp.forwarder else None
                })
            # convert to dataframe and merge with the PE metadata df
            df_eat = pd.DataFrame(rows)
            merged_df = pd.merge(df_eat, df_metadata, how="cross")
            return merged_df        
        else:
            return None

    except Exception as e:
        print(f"Error parsing exports for {file_path}: {e}")
        return None

def calculate_pe_risk_score(config):
    """
    Calculates a risk score (0-10) based on multiple telemetry points.
    Input: The merged DataFrame from process_pe_source.
    """
    # validation, this should have been done already, but we won't get far without the source_path
    file_path = config.get('source_path')    
    if not os.path.exists(file_path):
        return None

    # this isn't used currently but might be helpful
    correlation_id = config.get('correlation_id', str(uuid.uuid4())) 
    
    # Collect Data
    df_meta = get_pe_metadata(config)
    df_iat = get_iat_dataframe(config)
    
    if df_meta is not None and df_iat is not None:
        # Merge on correlation id - this won't work since i don't currently use the value
        enriched_df = pd.merge(df_iat, df_meta, on="correlation_id", how="left")
    
    if enriched_df is None or enriched_df.empty:
        return 0.0

    score = 0.0
    
    # 1. Extension Mismatch (High Priority: +3.0)
    # If the file is MZ but named .jpg or .txt, it's highly suspicious.
    if enriched_df['extension_mismatch'].any():
        score += 3.0

    # 2. Suspicious API Density (Medium Priority: Up to +4.0)
    suspicious_count = enriched_df[enriched_df['is_suspicious'] == True]['function'].nunique()
    if suspicious_count > 0:
        # Scale: 1 API = +1.0, 3+ APIs = +4.0
        api_score = min(suspicious_count * 1.0, 4.0)
        score += api_score

    # 3. Critical Combinations (Injection Pattern: +2.0)
    # Check for the "Injection Trifecta": Alloc + Write + RemoteThread
    funcs = enriched_df['function'].tolist()
    injection_pattern = {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'}
    if injection_pattern.issubset(set(funcs)):
        score += 2.0

    # 4. Persistence Check (+1.0)
    if any(cat == "Persistence" for cat in enriched_df['risk_category']):
        score += 1.0

    # Cap the score at 10.0
    return min(score, 10.0)