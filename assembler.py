import subprocess

def disassemble_exe(exe_file, output_file):
    subprocess.run(['objdump', '-d', '-M', 'intel', exe_file], stdout=output_file)
    print(f"{exe_file} sikeresen diszasszemblálva assembly kóddá: {output_file}")

if __name__ == "__main__":
    input_exe = input("Kérlek add meg az exe fájlt: ")
    output_asm = input("Kérlek add meg a kimeneti assembly fájl nevét: ")
    with open(output_asm, 'w') as output_file:
        disassemble_exe(input_exe, output_file)