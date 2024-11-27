import json
from idaapi import *
from idc_bc695 import *
# from idc import *
import idautils
import time
import re

'''
获得危险函数名称及对应位置信息
使用JSON文件的形式保存
'''
# 创建数据结构
data = {
    "title": "IDAPython危险函数调用检测",
    "arch": '',
    "endian": '',
    "dangerous-origin": 0,
    "dangerous": 0,
    "command": 0,
    "type1": 0,  #1型敏感函数
    "type2": 0,  #2型敏感函数
    "cmd-type":0,  #系统函数
    "danger-functions": []
}
# Todo:change to 2 type
dangerous_functions = [
    "gets",     # 从输入流读取字符串到缓冲区:char *gets(char *string)
    "strcpy",   # 字符串复制:char *strcpy(char *dest, const char *src)
    "strncpy",   # char *strncpy(char *dest, const char *src, size_t n)
    "strcat",   # 字符串连接:char* strcat(char* dest, char* src)
    "sprintf",  # 打印字符串到缓冲区:int sprintf( char *buffer, const char *format [, argument,...] )
    "vsprintf", # 打印字符串到缓冲区:int vsprintf(char *str, const char *format, va_list arg)
    "scanf",    # 从控制台输入 ，函数原型：int scanf（格式化字符串，输入列表）
    "fprintf",  # 将格式化数据输出到文件流中:int fprintf(FILE *stream, const char *format, ...)
    "sscanf",   # 从指定字符串输入，函数原型：int sscanf(字符串指针, 格式化字符串, 输入列表 )
    "fscanf",   # 从文件输入 ，函数原型：int fscanf(文件指针，格式字符串，输入列表)；
    "vfscanf",  # 在fscanf基础上增加了一个参数：va_list
    "vscanf",   # 在scanf基础上增加了一个参数 ：va_list
    "vsscanf",  # 在sscanf基础上增加了一个参数 ：va_list
    "fread",     # 从文件中读取二进制数据，size_t fread(void *ptr, size_t size, size_t count, FILE *stream);
]


attention_function = [
    "printf",   # 打印格式化字符串
    "strdup"    # 直接把要复制的内容复制给没有初始化的指针，因为它会自动分配空间给目的指针。所需空间由malloc()函数分配且可以由free()函数释放。char* strdup(const char* src);
    "streadd",
    "strecpy",
    "strtrns",
    "realpath",
    "syslog",
    "getopt",
    "getopt_long",
    "getpass",
    # ssize_t read(int fd, void *buf, size_t count);  从打开的设备或文件中读取数据,保存在缓冲区buf中
    "read",
    "getenv",  # 获取环境变量 char *getenv(const char *name)
    "getchar",
    "fgetc",
    "getc",
    "bcopy",
    "fgets",
    # void *memcpy(void *str1, const void *str2, size_t n)  从存储区 str2 复制 n 个字节到存储区 str1。
    "memcpy",
    "strccpy",
    "strcadd",
    "vsnprintf",
    "sscanf",
    "strncat",  # char *strncat(char *dest, const char *src, size_t n)
    "snprintf",
    "vprintf"
]

# 三个值分别表示函数的数据源、数据目的地址、参数个数
# -1表示目的地址为返回值，0表示待定
function_src_dest = {
    "gets": [1, -1, 1],
    "strdup": [1, -1, 1],
    "getenv": [1, -1, 1],
    "strcpy": [2, 1, 2],
    "strcat": [2, 1, 2],
    "sprintf": [0, 1, 0],
    "vsprintf": [3, 1, 0],
    "fprintf": [0, 1, 0],
    "scanf": [-1, 0, 0],
    "sscanf": [1, 0, 0],
    "fscanf": [1, 0, 0],
    "vfscanf": [1, 0, 0],
    "vscanf": [-1, 0, 0],
    "vsscanf": [1, 0, 0],
    "strncpy": [2, 1, 3],
    "strncat": [2, 1, 3],
    "memcpy": [2, 1, 3],   # memcpy(void *dest, const void *src, size_t n)
    "read": [1, 2, 3],
    "fread":[4,1,4]
}

format_function_offset_dict = {
    "sprintf": 2,
    "scanf": 1,
    "sscanf": 2,
    "snprintf": 3,
    "vprintf": 1,
    "printf": 1,
    "vsprintf": 2,
    "fscanf": 2,
    "vfscanf": 2,
    "vscanf": 1,
    "vsscanf": 2
}

command_execution_function = [
    "system",   # int system(const char *command);  执行命令行指令，返回命令的退出状态码。
    # FILE *popen(const char *command, const char *type);  打开一个进程，与该进程进行读写操作，并返回一个文件指针。
    "popen",
    "unlink",   # int unlink(const char *pathname);  删除指定的文件，返回删除的状态码。
    # int execv(const char *path, char *const argv[]);  执行指定路径的程序，其中 argv 参数用于传递程序的命令行参数，envp 参数用于传递程序的环境变量。
    "execv",
    # int execve(const char *path, char *const argv[], char *const envp[]);
    "execve",
    "execvp",   # int execvp(const char *file, char *const argv[]);
    # int execvpe(const char *file, char *const argv[], char *const envp[]);
    "execvpe",
    # int execl(const char *path, const char *arg, ...);  用于执行指定路径的程序，其中 arg 和可变参数列表用于传递程序的命令行参数，envp 参数用于传递程序的环境变量。
    "execl",
    # int execle(const char *path, const char *arg, ..., char *const envp[]);
    "execle",
    "execlp"    # int execlp(const char *file, const char *arg, ...);
]

# 定义函数，接受两个参数：起始地址和寄存器编号
# 在mips中，函数的参数要么是调用地址的后第一条指令，要么是调用地址前，且保存在寄存器$a0,$a1..中
# Todo:超出函数或基本块范围了，可能就是直接使用原寄存器中的值，特别是原寄存器存储的是函数参数的情况


def getArgAddr(start_addr, regNum):
    # 最多搜索的指令数
    scan_deep = 50
    # 初始化计数器
    count = 0
    if arch == 'mips' or arch == 'MIPS':
        # ！！定义一些特定的汇编指令助记符，用于后续判断！！
        mipscondition = ["bn", "be", "bg", "bl"]
        # ！！将寄存器编号转换为字符串，并构造出相应的寄存器名称！！
        reg = "$a" + str(regNum)
        # 尝试获取下一条指令的地址
        next_addr = Rfirst(start_addr)
        # 如果下一条指令存在且使用了指定的寄存器，则返回该指令地址
        if next_addr != BADADDR and reg == GetOpnd(next_addr, 0):
            return next_addr

        # 如果下一条指令不存在或者没有使用指定的寄存器，则在指定地址之前的指令中搜索
        before_addr = RfirstB(start_addr)
        while before_addr != BADADDR:
            # print(hex(before_addr))
            # 如果找到了使用指定寄存器的指令
            if reg == GetOpnd(before_addr, 0):
                # 判断该指令是否是条件分支指令，如果是则跳过该指令
                Mnemonics = GetMnem(before_addr)
                if Mnemonics[0:2] in mipscondition:
                    pass
                # 判断该指令是否是跳转指令，如果是则跳过该指令
                elif Mnemonics[0:1] == "j":
                    pass
                # 如果该指令不是条件分支指令或跳转指令，则返回该指令地址
                else:
                    return before_addr

            # 统计搜索的指令数，如果超过了最大搜索数，则退出循环
            count = count + 1
            if count > scan_deep:
                break

            # 继续向前搜索指令
            before_addr = RfirstB(before_addr)

        # 如果在搜索过程中没有找到使用指定寄存器的指令，则返回 BADADDR
        return BADADDR
    elif arch == 'arm' or arch == 'ARM':
        armcondition = ['BEQ', 'BNE', 'BGE', 'BLT', 'BGT', 'BLE', 'CMP']
        # ！！将寄存器编号转换为字符串，并构造出相应的寄存器名称！！
        reg = "R" + str(regNum)
        # 如果下一条指令不存在或者没有使用指定的寄存器，则在指定地址之前的指令中搜索
        # ARM架构中参数都在调用指令
        before_addr = RfirstB(start_addr)
        while before_addr != BADADDR:
            # 如果找到了使用指定寄存器的指令
            if reg == GetOpnd(before_addr, 0):
                # 判断该指令是否是条件分支指令，如果是则跳过该指令
                Mnemonics = GetMnem(before_addr)
                if Mnemonics[0:3] in armcondition:
                    pass
                # 判断该指令是否是跳转指令，如果是则跳过该指令,b、bl、bx 、blx
                elif Mnemonics[0:1] == "B":
                    pass
                # 如果该指令不是条件分支指令或跳转指令，则返回该指令地址
                else:
                    return before_addr

            # 统计搜索的指令数，如果超过了最大搜索数，则退出循环
            count = count + 1
            if count > scan_deep:
                break

            # 继续向前搜索指令
            before_addr = RfirstB(before_addr)

        # 如果在搜索过程中没有找到使用指定寄存器的指令，则返回 BADADDR
        return BADADDR
    else:
        return BADADDR

# 定义函数，接受两个参数：起始地址和寄存器编号


def getArg(start_addr, regNum):
    if arch == 'mips' or arch == 'MIPS':
        # 定义一些特定的汇编指令助记符，用于后续判断
        mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
        # 调用 getArgAddr 函数，获取寄存器使用位置
        arg_addr = getArgAddr(start_addr, regNum)
        # 如果获取成功，则进行下一步操作
        if arg_addr != BADADDR:
            # 获取使用该寄存器的指令助记符
            Mnemonics = GetMnem(arg_addr)
            # adds=['add','addu','addi','addiu']
            # subs=['sub','subu','subi','subiu']
            # print(Mnemonics[0:3])
            # 如果助记符是 add 指令，则解析寄存器参数，生成相应的参数字符串
            if Mnemonics[0:3] == 'add':
                if GetOpnd(arg_addr, 2) == "":
                    arg = GetOpnd(arg_addr, 0) + "+" + GetOpnd(arg_addr, 1)
                else:
                    arg = GetOpnd(arg_addr, 1) + "+" + GetOpnd(arg_addr, 2)
                # print(arg)
            # 如果助记符是 sub 指令，则解析寄存器参数，生成相应的参数字符串
            elif Mnemonics[0:3] == 'sub':
                if GetOpnd(arg_addr, 2) == "":
                    arg = GetOpnd(arg_addr, 0) + "-" + GetOpnd(arg_addr, 1)
                else:
                    arg = GetOpnd(arg_addr, 1) + "-" + GetOpnd(arg_addr, 2)
            # 如果助记符是在 mipsmov 列表中，则获取第二个参数作为参数字符串
            elif Mnemonics in mipsmov:
                arg = GetOpnd(arg_addr, 1)
            # 否则，获取指令反汇编字符串，并去除注释部分作为参数字符串
            else:
                arg = GetDisasm(arg_addr).split("#")[0]

            # 在使用该指令的地址上添加注释信息，说明该地址是第几个参数的值
            MakeComm(arg_addr, "addr: 0x%x " % start_addr +
                     "-------> arg" + str((int(regNum)+1)) + " : " + arg)
            # 返回解析出的参数字符串
            return arg
        else:
            # 如果获取失败，则返回 "get fail"
            return "get fail"
    elif arch == 'arm' or arch == 'ARM':
        armmov = ['MOV', 'MOVT', 'MOVW', 'LDR', 'LDRB', 'LDRH', 'STRBEQ']
        arg_addr = getArgAddr(start_addr, regNum)
        if arg_addr != BADADDR:
            Mnemonics = GetMnem(arg_addr)
            if Mnemonics[0:3] == "ADD":
                if GetOpnd(arg_addr, 2) == "":
                    arg = GetOpnd(arg_addr, 0) + "+" + GetOpnd(arg_addr, 1)
                else:
                    arg = GetOpnd(arg_addr, 1) + "+" + GetOpnd(arg_addr, 2)
            elif Mnemonics[0:3] == "SUB":
                if GetOpnd(arg_addr, 2) == "":
                    arg = GetOpnd(arg_addr, 0) + "-" + GetOpnd(arg_addr, 1)
                else:
                    arg = GetOpnd(arg_addr, 1) + "-" + GetOpnd(arg_addr, 2)
            elif Mnemonics[0:3] == "RSB":
                if GetOpnd(arg_addr, 2) == "":
                    arg = GetOpnd(arg_addr, 1) + "-" + GetOpnd(arg_addr, 0)
                else:
                    arg = GetOpnd(arg_addr, 2) + "-" + GetOpnd(arg_addr, 1)
            elif Mnemonics in armmov:
                arg = GetOpnd(arg_addr, 1)
            else:
                arg = GetDisasm(arg_addr).split(";")[0]
            MakeComm(arg_addr, "addr: 0x%x " % start_addr +
                     "-------> arg" + str((int(regNum)+1)) + " : " + arg)
            return arg
        else:
            return "get fail"
    else:
        return "unknow arch, get fail"


def checkRegIsStr(addr, reg, block_addr):
    # 可能该寄存器不在当前块，所以导致定位错误
    if addr < block_addr:
        return 'reg far away'
    pattern = r'a[A-Z]+'
    regChange=['MOV','LDR']
    # print(hex(block_addr))
    while not re.search(pattern,reg):
        # print(reg, hex(addr))
        if GetOpnd(addr, 0)==reg and GetMnem(addr) in regChange:
            reg = GetOpnd(addr, 1)
        if addr==block_addr:
            break
        addr = RfirstB(addr)
    return reg

# 定义函数，接受一个参数：字符串格式化指令的地址
def getFormatString(call_addr, arg_num, block_addr):
    # 初始化操作数编号
    op_num = 1
    # GetOpType Return value
    # define o_void        0  // No Operand                           ----------
    # define o_reg         1  // General Register (al, ax, es, ds...) reg
    # define o_mem         2  // Direct Memory Reference  (DATA)      addr
    # define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    # define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    # define o_imm         5  // Immediate Value                      value
    # define o_far         6  // Immediate Far Address  (CODE)        addr
    # define o_near        7  // Immediate Near Address (CODE)        addr
    # define o_idpspec0    8  // IDP specific type
    # define o_idpspec1    9  // IDP specific type
    # define o_idpspec2   10  // IDP specific type
    # define o_idpspec3   11  // IDP specific type
    # define o_idpspec4   12  // IDP specific type
    # define o_idpspec5   13  // IDP specific type
    
    # Todo:添加一个逻辑，如果addr对应的指令是ADD等，且操作数中存在寄存器，则继续跟踪该寄存器，直到函数起始地址
    addr = getArgAddr(call_addr, arg_num-1)
    # 获取立即数对应的字符串名称，并通过 LocByName 函数获取字符串地址
    if arch == 'mips' or arch == 'MIPS':
        # 获取第二个操作数类型，如果不是立即数，则将操作数编号加 1
        if (GetOpType(addr, op_num) != 5):
            op_num = op_num + 1
        # 如果第二个操作数还不是立即数，则返回 "get fail"
        if GetOpType(addr, op_num) != 5:
            return "get fail"
        op_string = GetOpnd(addr, op_num).split(" ")[0].split(
            "+")[0].split("-")[0].replace("(", "")
        # print(op_string)
    elif arch == 'arm' or arch == 'ARM':
        target = GetOpnd(addr, op_num)
        # 寄存器的来源仍是寄存器的情况
        if re.search(r'R[0-9]', target):
            target = checkRegIsStr(addr, target, block_addr)
        # 否则，判断寄存器中是否为格式化字符串
        pattern = r'a[A-Z]+'
        if not re.search(pattern, target):
            op_num = op_num + 1
            target = GetOpnd(addr, op_num)
        if target == '' or not re.search(pattern, target):
            return "get fail"
        pattern2 = r'a[A-Z][a-zA-Z0-9]*'
        match = re.search(pattern2, target)
        op_string = match.group(0)
    else:
        return "get fail"
    string_addr = LocByName(op_string)
    # 如果字符串地址不存在，则返回 "get fail"
    if string_addr == BADADDR:
        return "get fail"
    print(hex(string_addr))
    # 通过 get_string_at_address 函数获取字符串内容，并返回字符串地址和内容的列表
    # string = str(get_strlit_contents(string_addr)).split('\'')[1]
    string = str(get_strlit_contents(string_addr))
    # 打印字符串地址和内容
    # print("0x%x" % string_addr,string)
    return [string_addr, string]


global temp_buf_size


def get_arg_simple_func(call_addr, arg_num,block_addr):
    global temp_buf_size
    """
    获取函数调用位置 ref 的传入的 arg_num 个参数
    """
    # 创建一个列表，用于存储审计结果
    ret_list = {}
    # 获取函数栈帧大小，并将其格式化成16进制字符串，然后添加到审计结果列表中
    local_buf_size = GetFunctionAttr(call_addr, FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        return None
    else:
        temp_buf_size = local_buf_size
        local_buf_size = "0x%x" % local_buf_size
    # 获取函数调用时传递的参数，并将它们添加到审计结果列表中
    args = []
    # 获取函数调用时传递的参数，并将它们添加到审计结果列表中
    for num in range(0, arg_num):
        args.append(getArg(call_addr, num))
    ret_list["args"] = args
    # 将函数栈帧大小添加到审计结果列表中
    ret_list["buf_size"] = local_buf_size
    # 返回审计结果列表
    return ret_list

# Todo:1—>N Funcs
def get_arg_format_func(call_addr, arg_num, block_addr):
    """
    获取格式化函数调用位置 call_addr 的传入的 arg_num 个参数
    """
    # 创建一个列表，用于存储审计结果
    ret_list = {}

    # 获取格式化字符串的地址，并获取格式化字符串及其地址
    string_and_addr = getFormatString(call_addr, arg_num, block_addr)
    if string_and_addr == "get fail":
        # 不能确定有多少个参数，只能先找一个
        fmt_num = 1
        ret_list["format_addr"] = "get fail"
        ret_list["format_str"] = "get fail"
    else:
        fmt_num = string_and_addr[1].count("%")
        ret_list["format_addr"] = "0x%x" % string_and_addr[0]
        ret_list["format_str"] = string_and_addr[1]
    args = []
    # 获取函数调用时传递的参数，并将它们添加到审计结果列表中
    for num in range(0, arg_num+fmt_num):
        args.append(getArg(call_addr, num))
    ret_list["args"] = args
    return ret_list


def check_func(funcName, ref, block_addr):
    print(funcName, ": 0x%x" % ref, "------------")
    if funcName in format_function_offset_dict:
        res = get_arg_format_func(
            ref, format_function_offset_dict[funcName], block_addr)
        print(res)
        # return res["format_addr"] == "get fail" or "%s" in res["format_str"]
        # 匹配不到的先不管
        return "%s" in res["format_str"]
    else:
        if funcName in command_execution_function:
            res = get_arg_simple_func(ref, 1, block_addr)
            check_num = 1
        else:
            res = get_arg_simple_func(ref, function_src_dest[funcName][2], block_addr)
            check_num = function_src_dest[funcName][0]
        if not res:
            return False
        print(res)
        pattern = r'a+[A-Z]'
        # 排除直接以字符串为参数的情况
        if check_num != -1 and check_num != 0:
            target=res["args"][check_num-1]
            target=checkRegIsStr(ref,target,block_addr)
            print(target)
            return not re.search(pattern, target)
        return True


def get_arch():
    """获取分析文件架构和大小端"""
    inf = idaapi.get_inf_structure()
    if inf.is_64bit():
        arch = "x64"
        endianness = sys.byteorder
    elif inf.is_32bit():
        if idaapi.ph_get_id() == idaapi.PLFM_MIPS:
            arch = "MIPS"
        elif idaapi.ph_get_id() == idaapi.PLFM_ARM:
            arch = "ARM"
        else:
            arch = "x86"
        endianness = "big" if inf.is_be() else "little"
    elif inf.is_16bit():
        arch = "x16"
        endianness = "unknown"
    elif inf.is_8bit():
        arch = "x8"
        endianness = "unknown"
    else:
        arch = "Unknown"
        endianness = "unknown"
    return arch, endianness


# 在全局定义架构和大小端
arch, endianness = get_arch()
data['arch'] = arch
data['endian'] = endianness

print("Loading the dangerous library file...")
# 需要寻找的函数名，此函数可以确定CPU支持哪些特性
danger_funcs = {'dangerous': dangerous_functions,'command': command_execution_function}
# danger_funcs = {'dangerous': dangerous_functions}
print("Start searching for danger functions,Potential vulnerabilities will be printed below,Please wait...")

# 漏洞名称及地址
vulnerabilities = data["danger-functions"]
for type, funcs in danger_funcs.items():
    for funcName in funcs:
        print(funcName+'--!!!!!!!!!!!!!!!!!!!!!!!!!!')
        addr = LocByName(funcName)
        if addr != BADADDR:
            # 当前危险函数类型对应的所有被索引地址
            cross_refs = CodeRefsTo(addr, 0)
            print("Cross References to %s" % funcName)
            print("-------------------------------")
            vulnerability = {
                "function-name": funcName
            }
            # 找到每个索引地址
            for ref in cross_refs:
                # 获取包含给定地址的函数
                func = get_func(ref)
                # if(function_src_dest[funcName][1]==0):
                #     data["type2"]+=1
                # else:
                #     data["type1"]+=1
                if func:
                    # 获取函数起始地址
                    func_start = func.start_ea
                    block_addr = func_start
                    # 遍历函数的所有基本块
                    for block in FlowChart(func):
                        # 如果给定地址在当前基本块中，则获取基本块起始地址
                        if block.start_ea <= ref < block.end_ea:
                            block_addr = block.start_ea
                            break
                    # 这里还需要额外判断该索引对应的危险函数参数是否可能被污染
                    # print("++++++++++++",funcName)
                    data['dangerous-origin']+=1
                    if check_func(funcName, ref, block_addr):
                        address = {
                            "vulnerability": hex(ref),
                            "caller-start": hex(func_start),
                            "slock": hex(block_addr)
                        }
                        vulnerability["address"] = address.copy()
                        if funcName in function_src_dest:
                            vulnerability["key_reg"] = function_src_dest[funcName][1]-1
                        else:
                            # 需要具体分析
                            vulnerability["key_reg"] = -1
                        # 如果目的地址为0，则为2型敏感函数
                        if funcName not in function_src_dest:
                            data["cmd-type"] +=1
                            vulnerability["type"] = 3
                        else:
                            if(function_src_dest[funcName][1]==0):
                                data["type2"]+=1
                                vulnerability["type"] = 2
                            else:
                                data["type1"]+=1
                                vulnerability["type"] = 1
                        vulnerabilities.append(vulnerability.copy())
                        data[type] += 1
                        # print("0x%x" % ref)
                        SetColor(ref, CIC_ITEM, 0x00dddd)

# 将数据写入JSON文件
with open(get_root_filename()+'_analysis_report_'+str(round(time.time()))+'.json', 'w') as f:
    json.dump(data, f, indent=4)

print("Danger functions search ended")
