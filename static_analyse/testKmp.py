MIN_CHECK_LEN = 150

def get_prefix(substring):
    """
    计算子串的前缀函数
    """
    n = len(substring)
    prefix = [0] * n
    j = 0
    for i in range(1, n):
        while j > 0 and substring[j] != substring[i]:
            j = prefix[j-1]
        if substring[j] == substring[i]:
            j += 1
        prefix[i] = j
    return prefix

def kmp(substring, string, min_len=0, s_prefix=None):
    """
    在字符串中查找子串，返回是否找到以及子串在字符串中的起始位置
    """
    m = len(substring)
    n = len(string)
    if m == 0 or n == 0 or m > n or n < min_len:
        return False, -1

    if s_prefix is None:
        s_prefix = get_prefix(substring)

    i, j = 0, 0
    while i < n:
        if string[i] == substring[j]:
            i += 1
            j += 1
            if j == m:
                return True, i - j
        elif j > 0:
            j = s_prefix[j-1]
        else:
            i += 1
    return False, -1

def check_binary_files():
    filename1 = 'G:/ysq/固件/qiling仿真/unsubPublic_UPNP_Event_1'
    with open(filename1, 'rb') as f1:
        binary_data1 = f1.read()
    print(binary_data1)
    # print(' '.join([hex(x) for x in binary_data1]))

    receive="1ccee668-0f15-8d2c-38d8-044dd194e7af\r\n\r\n"
    binary_data2 = bytes(receive,'utf-8')  # 将字符串转换为二进制串
    print(binary_data2)
    # print(' '.join([hex(x) for x in binary_data2]))
    
    s_prefix = get_prefix(binary_data2)
    res = kmp(binary_data2, binary_data1, MIN_CHECK_LEN, s_prefix)
    if res:
        print("找到匹配模式")
    else:
        print("未找到匹配模式")

check_binary_files()
# print('a'*64)