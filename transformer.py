# %%
import json
import pandas as pd
import numpy as np

# %%
def read_table (filename):
    return pd.read_csv(filename, sep=";", index_col=0 )

# %%

config_table = read_table("ConfigTable.csv")
mask_table = read_table("MaskTable.csv")

def toJSON (ASM_byte, first_byte):
    if (ASM_byte!=''):
        mask_byte = mask_table[first_byte[0]][first_byte[1]]
        ASM_byte = int (ASM_byte, 16)
        mask_byte = int (mask_byte, 16)
        return str(hex(ASM_byte & mask_byte))[2:]




print(config_table)
print(mask_table)




# %%
import sys
import os
from tqdm import tqdm

main_dir = sys.argv[1]
output_dir = sys.argv[2]

for f in tqdm(os.listdir(main_dir), desc="Masking files", unit="file"):
    file_path = os.path.join(main_dir,f)
    with open (file_path, "r") as file:
        sorok = file.readlines()
        header =''
        commands = []
        ASM_byte = ''
        data = {"processes": []}
        for sor in sorok :
            prev_header = header
            if sor.__contains__('>:'):
                new_process = {}
                header = sor.split('<')[0]
                new_process['header'] = header
                commands = []
            elif (sor.__contains__(':')):
                sor = sor.split(':')[1]
                if (sor.__contains__(' ') and sor[0]!=' '):
                    sor = sor.split(' ')
                    first_byte = sor[0].strip('\t').upper()
                    bytes = config_table[first_byte[0]][first_byte[1]]
                    for x in range(bytes):
                        ASM_byte= ASM_byte+sor[x]
                
                    commands.append(toJSON(ASM_byte, first_byte))
                    ASM_byte=''  

            if (prev_header!= header and header!=''):
                new_process["commands"] = commands
                data["processes"].append(new_process)
            
        output_file_path = os.path.join(output_dir, f"{os.path.splitext(f)[0]}.json")
        with open(output_file_path, "w") as json_file:
            json.dump(data, json_file, indent=4)


