import sys, os, magic

systemCmds=['rm', 'get', 'mdev','sysconf']

def is_program(dir,file):
    ss=file.split(' ')
    # print(ss)
    for s in ss:
        s.strip().strip('\"')
        if os.path.exists(dir+'/'+s) or os.path.exists(rootfs+'/'+s) or s.isalpha():
            if s not in systemCmds:
                target_binaries.add(s)
            break

def find_program(rcS):
    # file_type = magic.from_file(rcS, mime=True)
    # if file_type != 'text/plain': 
    #     return
    if not os.path.exists(rcS):
        return 
    print(rcS)
    if 'rcS' in rcS or '.sh' in rcS or 'inittab' in rcS:
        file = open(rcS)
        for line in file.readlines():
            line = line.strip()
            if len(line) == 0:
                continue
            elif line[0] == '#' or 'mkdir ' in line or 'date ' in line or 'sleep ' in line or 'mount ' in line or 'cat ' in line or 'echo ' in line or 'PATH=' in line or 'insmod ' in line or 'export ' in line or 'cp ' in line or 'chmod ' in line or 'if ' in line or 'fi' in line:
                continue
            elif 'sh' in line:
                if 'sh ' in line:
                    target_file = line.split('sh ')[1].strip()
                else:
                    target_file = line.split(' ')[0].strip()
                if '.sh' in target_file:
                    find_program(rootfs+target_file.strip('&').strip())
                else:
                    is_program(rootfs,target_file)
                #print(target_file)
            else:
                target_file = line.split(' ')[0].strip('&')
                # print(line.strip('&'))
                is_program(rootfs, target_file)
        file.close()

rootfs = sys.argv[1]
target_binaries=set()
#os.system(f'find {rootfs} -name *rcS*')
for root, dirs, files in os.walk(rootfs):
    for dir in dirs:
        if 'init' in dir:
            for rr, dds, ffs in os.walk(os.path.join(root, dir)):
                for name in ffs:
                    target = os.path.join(rr, name)
                    find_program(target)
    for name in files:
        if '.cgi' in name:
            print(root)
            is_program(root,name)
        elif 'rcS' in name or 'init' in name:
            # print(f'find {target}')
            find_program(name)

print(target_binaries)
print('service program:', len(target_binaries))




