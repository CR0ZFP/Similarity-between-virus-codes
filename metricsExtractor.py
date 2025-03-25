# %% [markdown]
# ## Ha nincs letöltve a python kernel kérem töltse le vagy az extensionok-ből vagy a microsoft store-ból
# Ha a jupiter notebook sincs letöltve, kérem azt is töltse le az extensionok-ből
# 

# %% [markdown]
# ## Imports
# Itt láthat kikommentezett részeket, ha ezek a libary-k nincsenek meg akkor ezeket is fel kell pipelni. Csak vegye ki a kommentet és úgy futtassa le

# %%
#!pip install pandas
#!pip install pefile
import os
import hashlib
import math
import pefile
import pandas as pd

# %% [markdown]
# Features:

# %%
def file_size(filepath):
    return os.path.getsize(filepath)


"""""
def calculate_entropy(section_data):
    byte_freq = [0] * 256
    for byte in section_data:
        byte_freq[byte] += 1
    entropy = 0
    for freq in byte_freq:
        if freq > 0:
            p_x = freq / len(section_data)
            entropy -= p_x * math.log2(p_x)
    return entropy
"""""

def calculate_entropy(data):
    if isinstance(data, bytes):  # Ha a bemenet bytes típusú, alakítsd listává
        data = list(data)
        
    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1
    entropy = 0
    for freq in byte_freq:
        if freq > 0:
            p_x = freq / len(data)
            entropy -= p_x * math.log2(p_x)
    return entropy

def calculate_file_entropy(filepath):
    with open(filepath, "rb") as f:
        file_data = f.read()  # Fájl teljes tartalmának beolvasása
    return calculate_entropy(file_data)

def extract_sections(pe):
    section_features = []
    for section in pe.sections:
        section_features.append({
            "section_name": section.Name.decode('utf-8').strip(),
            "section_size": section.SizeOfRawData,
            "section_entropy": calculate_entropy(section.get_data()),
            "section_characteristics": section.Characteristics
        })
    return section_features

def extract_imports(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
    return 0

def extract_exports(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    return 0

def calculate_hash(filepath):
    with open(filepath, "rb") as f:
        file_data = f.read()
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
    return md5_hash, sha256_hash

def extract_import_details(pe):
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                imports.append({
                    "dll": dll_name,
                    "function": imp.name.decode('utf-8') if imp.name else None
                })
    return imports


def extract_export_details(pe):
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(symbol.name.decode('utf-8') if symbol.name else None)
    return exports


# %% [markdown]
# Extract features:

# %%
def extract_pe_features(filepath):
    pe = pefile.PE(filepath)
    file_hashes = calculate_hash(filepath)
    sections = extract_sections(pe)

    features = {
        "file name": os.path.basename(filepath),
        "file_size": file_size(filepath),   #a teljes exe merete byteban

        "file_entropy": calculate_file_entropy(filepath), #a teljes exe entropiajat adja meg (magas entropia -> tomorites/titkositas -> potencionalis virus)

        "num_sections": len(pe.sections),   #a fajl szekcioinak szamat mondja meg

        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,  #A belépési pont címe hexadecimálisan, ||||TIPIKUS: 0x1000  # A `.text` szekcióban található |||| GYANUS: 0x3000  # Egy szokatlan szekcióban található

        "characteristics": pe.FILE_HEADER.Characteristics,  #A fájl jellemzői ()

        "timestamp": pe.FILE_HEADER.TimeDateStamp,  #A PE fájl időbélyege Unix timestampként (fajl forditasanak ideje)

        "md5_hash": file_hashes[0],     #hash ertek szerint azonositja a teljes exet, ezek a train adatbazis hasonlosagat es a virusokat tartalmazo adatbazisokhoz jok (pl VirusTotal)
        "sha256_hash": file_hashes[1],

        "num_imports": extract_imports(pe), #importalt fuggvenyek szama

        "num_exports": extract_exports(pe), #exportalt dllek szama,

        "import_details": extract_import_details(pe),   #importalt fuggvenyek, dllek, stb nevei

        "export_details": extract_export_details(pe)    #exportalt fuggvenyek, dllek, stb nevei
    }

    # Add section-based features dynamically
    for i, section in enumerate(sections):  #minden sectionnek megmondja a nevét, entropyja, meretet, karakterisztikajat
        features[f"section_{i+1}_name"] = section["section_name"]
        features[f"section_{i+1}_size"] = section["section_size"]
        features[f"section_{i+1}_entropy"] = section["section_entropy"]
        features[f"section_{i+1}_characteristics"] = section["section_characteristics"]

    return features

# %% [markdown]
# Test Csv:

# %%
#test 1 exen
import sys
from tqdm import tqdm

main_path = str(sys.argv[1])  # A bemeneti fájl elérési útvonala
dataset_name = str(sys.argv[2])  # A kimeneti adathalmaz neve

def process_single_file(filepath, label):
    features = extract_pe_features(filepath)
    features["malicious"] = label  # Add label (0 for benign, 1 for malicious)
    return features

malicious_df = pd.DataFrame()
#main_path=r"C:\Users\Dogo\Desktop\exe" #Teljes elérési útvonala a fertőzött exe fileoknak
malicious_data_list = []

for file in tqdm(os.listdir(main_path), desc="Processing files", unit="file"): #Kilistázunk minden exe file-t ami benne található

    malicious_file_path= os.path.join(main_path,file) #Az útvonalt és a file nevét összemergeljük
    with open (malicious_file_path, "rb") as file:
        magic = file.read(2)
    if magic == b"MZ": #Ha a file MZ-vel kezdődik, akkor exe file
        malicious_data = process_single_file(malicious_file_path, label=1) #Elkezdjük feldolgozni az összeset amíg végig nem érünk rajtuk 
        malicious_data_list.append(malicious_data)  #Csakis kizárólag .exe filok feldolgozására alkalmas, kérem ezt vegye figyelembe
    else:
        print(f"{file} is not an exe file")


malicious_df = pd.DataFrame(malicious_data_list)
# Save to CSV for future use
malicious_df.to_csv(dataset_name, index=False)
print("Training dataset saved to {dataset_name}")


