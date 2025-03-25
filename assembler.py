import subprocess
from tqdm import tqdm
import sys
import os

def disassemble_exe(exe_file, output_file):

    with open(output_file, "w") as f:
        subprocess.run(['objdump', '-d', '-M', 'intel', exe_file], stdout=f)
        print(f"{exe_file} sikeresen diszasszemblálva assembly kóddá: {output_file}")

if __name__ == "__main__":
    main_path = str(sys.argv[1])
    output_path = str(sys.argv[2])

    for file in tqdm(os.listdir(main_path), desc="Disassemble files", unit="file"):
        exe_file_path= os.path.join(main_path,file) #Az útvonalt és a file nevét összemergeljük
        with open (exe_file_path, "rb") as f:
            magic = f.read(2)
        if magic == b"MZ": #Ha a file MZ-vel kezdődik, akkor exe file
            asm_file_path = os.path.join(output_path, str.strip(f"{file}.asm"),".exe")
            disassemble_exe(exe_file_path, asm_file_path)