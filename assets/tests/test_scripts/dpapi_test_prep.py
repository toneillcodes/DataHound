import os
import struct
import uuid
import binascii

def create_mock_dpapi_environment(base_dir="test_lab"):
    # 1. Setup Directories
    protect_dir = os.path.join(base_dir, "Microsoft", "Protect", "S-1-5-21-123456789-123456789-123456789-1001")
    appdata_dir = os.path.join(base_dir, "Local", "Google", "Chrome", "User Data")
    os.makedirs(protect_dir, exist_ok=True)
    os.makedirs(appdata_dir, exist_ok=True)

    # Configuration
    MK_GUID = uuid.uuid4()
    DPAPI_MAGIC = binascii.unhexlify("01000000D08C9DDF0115D1118C7A00C04FC297EB")
    
    # 2. Create a Mock MasterKey File
    # Format: Version(4), Salt(16), Iterations(4)
    mk_path = os.path.join(protect_dir, str(MK_GUID))
    with open(mk_path, "wb") as f:
        f.write(struct.pack("<L", 2)) # Version 2
        f.write(os.urandom(16))      # Random Salt
        f.write(struct.pack("<L", 8000)) # 8000 Iterations
    
    # 3. Create a Mock DPAPI Blob (e.g., Chrome 'Login Data')
    # Format: Magic(20), Version(4), ProviderGUID(16), MKVersion(4), DescLen(4), Desc(UTF-16)
    blob_path = os.path.join(appdata_dir, "Login Data")
    description = "Google Chrome Password\x00".encode('utf-16le')
    desc_len = len(description)

    with open(blob_path, "wb") as f:
        f.write(DPAPI_MAGIC)             # Magic
        f.write(struct.pack("<L", 1))    # Version
        f.write(MK_GUID.bytes_le)        # MasterKey GUID
        f.write(struct.pack("<L", 1))    # MasterKey Version
        f.write(struct.pack("<L", desc_len)) # Description Length
        f.write(description)             # The Description
        f.write(os.urandom(100))         # Random "Encrypted" Data

    print(f"[+] Created Mock MasterKey: {mk_path}")
    print(f"[+] Created Mock Blob: {blob_path}")
    print(f"[!] Target MasterKey GUID for search: {MK_GUID}")

if __name__ == "__main__":
    create_mock_dpapi_environment()