import os
import struct
import pandas as pd
from datetime import datetime, timezone
import argparse

WINDOWS_TICKS_TO_UNIX_EPOCH = 116444736000000000
TICKS_PER_SECOND = 10000000


def convert_time_to_int(str_time):
    # 2024-10-11 13:10:51.000 -> 20241011131051000
    int_time = int(str_time.replace("-", "").replace(" ", "").replace(":", "").replace(".", ""))
    return int_time

def convert_filetime_to_datetime(byte_data):
    if isinstance(byte_data, int):
        filetime = byte_data
    else:
        filetime = struct.unpack('<Q', byte_data)[0]
    
    unix_timestamp = (filetime - WINDOWS_TICKS_TO_UNIX_EPOCH) / TICKS_PER_SECOND
    dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(dt.microsecond / 1000):03d}"


class RC4Variant:
    key_hex = '''1E 87 78 1B 8D BA A8 44 CE 69 70 2C 0C 78 B7 86
                A3 F6 23 B7 38 F5 ED F9 AF 83 53 0F B3 FC 54 FA
                A2 1E B9 CF 13 31 FD 0F 0D A9 54 F6 87 CB 9E 18
                27 96 97 90 0E 53 FB 31 7C 9C BC E4 8E 23 D0 53
                71 EC C1 59 51 B8 F3 64 9D 7C A3 3E D6 8D C9 04
                7E 82 C9 BA AD 97 99 D0 D4 58 CB 84 7C A9 FF BE
                3C 8A 77 52 33 55 7D DE 13 A8 B1 40 87 CC 1B C8
                F1 0F 6E CD D0 83 A9 59 CF F8 4A 9D 1D 50 75 5E
                3E 19 18 18 AF 23 E2 29 35 58 76 6D 2C 07 E2 57
                12 B2 CA 0B 53 5E D8 F6 C5 6C E7 3D 24 BD D0 29
                17 71 86 1A 54 B4 C2 85 A9 A3 DB 7A CA 6D 22 4A
                EA CD 62 1D B9 F2 A2 2E D1 E9 E1 1D 75 BE D7 DC
                0E CB 0A 8E 68 A2 FF 12 63 40 8D C8 08 DF FD 16
                4B 11 67 74 CD 0B 9B 8D 05 41 1E D6 26 2E 42 9B
                A4 95 67 6B 83 98 DB 2F 35 D3 C1 B9 CE D5 26 36
                F2 76 5E 1A 95 CB 7C A4 C3 DD AB DD BF F3 82 53'''
                
    key = bytes.fromhex(key_hex)
    
    def __init__(self, key=key):
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        self.key_schedule(key)

    def key_schedule(self, key: bytes):
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        # print(self.S)
        self.i = 0
        self.j = 0

    def process(self, data: bytes, ii = 0, jj = 0, offset: int = 0) -> bytes:
        i = ii
        j = jj
        i = self.i
        j = self.j
        S = self.S[:]
        result = bytearray()
        for index, byte in enumerate(data):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            result.append(byte ^ K)
        self.i = i
        self.j = j
        self.S = S
        return bytes(result)

FIELD_IDENTIFIER = {
    0x2:'CQuaResDataID_File',
    0x3:'CQuaResDataID_Registry',
    0xA:'Flags',
    0xC:'PhysicalPath',
    0xD:'DetectionContext',
    0xE:'Unknown',
    0xF:'CreationTime',
    0x10:'LastAccessTime',
    0x11:'LastWriteTime'
}

def arg_parser():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-o', type=str, help='Output Folder')
    parser.add_argument('-uj', type=str, help='$UsnJrnl')
    parser.add_argument('-df', type=str, help='Windows Defender Folder')

    args = parser.parse_args()
    if args.o == None:
        print(r"You have to input Output Folder using '-o'")
        os._exit(0)

    return args

def combine_N_list_E_list(N_list, E_list):
    
    S_list = list()
    N_list_len = len(N_list)
    E_list_len = len(E_list)
    N_idx = 0
    while N_idx < N_list_len:
        E_idx = 0
        while E_idx < E_list_len:
            if N_list[N_idx][2] == E_list[E_idx][2]: # compare F_path
                T_inject = convert_time_to_int(N_list[N_idx][9]) # T_inject
                M_Time = convert_time_to_int(E_list[E_idx][6]) # M_Time
                if abs(M_Time - T_inject) < 60000: # 1 minute 
                    tmp_S_list = [None] * 16
                    tmp_S_list[0] = None
                    tmp_S_list[1] = None
                    tmp_S_list[2] = E_list[E_idx][2]
                    tmp_S_list[3] = E_list[E_idx][3]
                    tmp_S_list[4] = E_list[E_idx][4]
                    tmp_S_list[5] = E_list[E_idx][5]
                    tmp_S_list[6] = E_list[E_idx][6]
                    tmp_S_list[7] = E_list[E_idx][7]
                    tmp_S_list[8] = E_list[E_idx][8]
                    tmp_S_list[9] = N_list[N_idx][9]
                    tmp_S_list[10] = None
                    tmp_S_list[11] = E_list[E_idx][11]
                    tmp_S_list[12] = "NE"
                    tmp_S_list[13] = E_list[E_idx][13]
                    tmp_S_list[14] = E_list[E_idx][14]
                    S_list.append(tmp_S_list)
                    
                    del N_list[N_idx]
                    del E_list[E_idx]
                    
                    N_list_len -= 1
                    E_list_len -= 1
                    N_idx -= 1
                    
                    break
                    
            E_idx += 1
            
        N_idx += 1
    
    S_list.extend(N_list)
    S_list.extend(E_list)
    
    return S_list

def combine_S_list_D_list(T_list, D_list):
    S_list = list()
    T_list_len = len(T_list)
    D_list_len = len(D_list)
    T_idx = 0
    while T_idx < T_list_len:
        D_idx = 0
        while D_idx < D_list_len:
            if ("E" in T_list[T_idx][12] and T_list[T_idx][13] == D_list[D_idx][13]):

                T_list[T_idx][0] = D_list[D_idx][0]
                T_list[T_idx][1] = D_list[D_idx][1]
                T_list[T_idx][10] = D_list[D_idx][10]
                T_list[T_idx][12] += D_list[D_idx][12]
                T_list[T_idx][15] = D_list[D_idx][15]
                S_list.append(T_list[T_idx])
                
                del T_list[T_idx]
                del D_list[D_idx]
                
                T_list_len -= 1
                D_list_len -= 1
                T_idx -= 1
                break
            D_idx += 1
        T_idx += 1
        
    T_list_len = len(T_list)
    D_list_len = len(D_list)
    T_idx = 0
    while T_idx < T_list_len:
        D_idx = 0
        while D_idx < D_list_len:
            T_T_det_del = convert_time_to_int(T_list[T_idx][11])
            D_T_det_del = convert_time_to_int(convert_filetime_to_datetime(D_list[D_idx][11]))
            tmp_flag = ("E" not in T_list[T_idx][12] and T_list[T_idx][2] == D_list[D_idx][2] and abs(D_T_det_del - T_T_det_del) < 180000)
            if tmp_flag:

                T_list[T_idx][0] = D_list[D_idx][0]
                T_list[T_idx][1] = D_list[D_idx][1]
                T_list[T_idx][10] = D_list[D_idx][10]
                T_list[T_idx][12] += D_list[D_idx][12]
                T_list[T_idx][15] = D_list[D_idx][15]
                S_list.append(T_list[T_idx])
                
                del T_list[T_idx]
                del D_list[D_idx]
                
                T_list_len -= 1
                D_list_len -= 1
                T_idx -= 1
                
                break

            D_idx += 1
        T_idx += 1
    
    S_list.extend(T_list)
    
    return S_list

def save_S_list_to_csv(S_list, out_path):
    columns = pd.MultiIndex.from_tuples([('Who', 'N_com'), ('Who', 'N_user'), 
                                         ('What_file', 'F_path'), ('What_file', 'F_size'), ('What_file', 'F_enc'), 
                                         ('What_sig', 'N_mal'), 
                                         ('When_inject', 'M_time'), ('When_inject', 'A_time'), ('When_inject', 'C_time'), ('When_inject', 'T_inject'), 
                                         ('How_inject', 'N_proc'), 
                                         ('When_det_del', 'T_det_del'), 
                                         ('Used_artifacts', 'flag'), ('Used_artifacts', 'N_ET_File'), ('Used_artifacts', 'N_RD_File'), ('Used_artifacts', 'N_DH_File')
                                         ])
    df = pd.DataFrame(S_list, columns=columns)
    
    df.to_csv(f'{out_path}\\S_list.csv', index=False)
    
if __name__ == "__main__":
    pass