import time,sys
from front_analysise.tools.traver import TraverFile
import subprocess,re

def write2file(output, filepath):
    with open(filepath, 'a') as file:
        file.write(output+'\n')

common_bins=['core','ip','upgrade','chat','nvram','et','usb','wins','time_check','lzma','taskset','cfm','test','unzip','unzip2','unbzip2']

# firmware_dir='/home/fuzz/ysq/firm-san/testTendaAC15/squashfs-root'
firmware_dir=sys.argv[1]
file_name=sys.argv[2]
target_firmware=firmware_dir+'/../'+file_name+'.extracted.'+str(round(time.time()))
traver = TraverFile(firmware_dir)
elfs = traver.get_elffile()
targets=set()
for elf in elfs:
    flag=1
    print(elf)    
    for b in common_bins:
        if elf.endswith(b):
            print(b)
            flag=0
            break
    if flag==1:
        targets.add(elf)

write2file('----------------------------------------------------',target_firmware)

def readelf_dynamic_section(filepath):
    command = ['readelf', '-d', filepath]
    output = subprocess.check_output(command).decode()
    return output

def extract_bracket_contents(string):
    pattern = r'\[(.*?)\]'  # 使用非贪婪模式匹配方括号中的内容
    matches = re.findall(pattern, string)
    return matches
DLLs=set()
common_libs=['libavcodec', 'libFLAC', 'libcrypt', 'libid3tag', 'libz', 'libntfs', 'libip6tc', 'libexif', 'libavutil','libjpeg','libcrypto',
             'libc','libavformat', 'libgcc_s', 'libdl', 'libxtables','libvorbis', 'libm', 'libogg','libsqlite3','libpthread','libresolv']
for t in targets:
    write2file(t,target_firmware)
    result=readelf_dynamic_section(t)
    libs=extract_bracket_contents(result)
    # print(libs)
    for lib in libs:
        if 'so' in lib:
            DLLs.add(lib)

write2file('----------------------------------------------------',target_firmware)
write2file("targets binaries:"+str(len(targets)),target_firmware)
write2file('----------------------------------------------------',target_firmware)
target_libs=[]
for lib in DLLs:
    flag=1
    for clib in common_libs:
        if clib in lib:
            flag=0
            break
    if flag==1:
        target_libs.append(lib)
        write2file(lib,target_firmware)

write2file('----------------------------------------------------',target_firmware)
write2file("target DLLs :"+str(len(target_libs)),target_firmware)
