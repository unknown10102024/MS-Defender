import os
import sys
import struct
import re
import json
import pandas as pd
from datetime import datetime, timezone


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

def open_MFT(path):
    # print(path)
    pass

def open_J(path):
    
    # print(path)
    pass


def open_ET(path):
    et_dict = dict()
    # print(path)
    uid_pattern = r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    file_list = list()
    os.makedirs(path+r"\decrypted", exist_ok=True)
    for file_name in os.listdir(path):
        file_path = os.path.join(path, file_name)
        
        if re.match(uid_pattern, file_name) and os.path.isfile(file_path):
            file_list.append(file_name)
            with open(file_path, 'rb') as f1:
                et_header = f1.read(0x3C)
                rc4 = RC4Variant()
                dec_et_header = rc4.process(et_header)
                # print(dec_et_header)
                et_section_1_len = struct.unpack('<I', dec_et_header[0x28:0x2C])[0]
                et_section_2_len = struct.unpack('<I', dec_et_header[0x2C:0x30])[0]
                et_section_1 = f1.read(et_section_1_len)
                et_section_2 = f1.read(et_section_2_len)
                rc4 = RC4Variant()
                dec_et_section_1 = rc4.process(et_section_1)
                rc4 = RC4Variant()
                dec_et_section_2 = rc4.process(et_section_2)
            
            # with open(path+r"\decrypted\\"+file_name+"_dec", 'wb') as f2:
            #     f2.write(dec_et_header+dec_et_section_1+dec_et_section_2)
            
            dec_et_file = dec_et_header+dec_et_section_1+dec_et_section_2
            magic_header = dec_et_header[:4]
            _ = dec_et_header[4:8]
            padding = dec_et_header[8:40]
            section_1_size = dec_et_header[40:44]
            section_2_size = dec_et_header[44:48]
            section_1_crc = dec_et_header[48:52]
            section_2_crc = dec_et_header[52:56]
            magic_footer = dec_et_header[56:60]
            # print()
            # print(f"magic_header: {magic_header}")
            # print(f"padding: {padding}")
            # print(f"section_1_size: {section_1_size}")
            # print(f"section_2_size: {section_2_size}")
            # print(f"section_1_crc: {section_1_crc}")
            # print(f"section_2_crc: {section_2_crc}")
            # print(f"magic_footer: {magic_footer}")
            _id = dec_et_section_1[:16]
            scan_id = dec_et_section_1[16:32]
            timestamp = dec_et_section_1[32:40]
            threat_id = dec_et_section_1[40:48]
            one = dec_et_section_1[48:52]
            detection_name = dec_et_section_1[52:].decode().rstrip('\x00')
            # print()
            # print(f"_id: {_id}")
            # print(f"scan_id: {scan_id}")
            # print(f"timestamp: {timestamp}")
            # print(f"threat_id: {threat_id}")
            # print(f"one: {one}")
            # print(f"detection_name: {detection_name}")
            entry_count = struct.unpack("<I", dec_et_section_2[:4])[0]
            # print()
            # print(f"entry_count: {entry_count}")
            
            et_dict["section_1_crc"] = struct.unpack('<I', section_1_crc)[0]
            et_dict["section_2_crc"] = struct.unpack('<I', section_2_crc)[0]
            et_dict["ditection_time"] = convert_filetime_to_datetime(timestamp)
            et_dict["malware_name"] = detection_name
            et_dict["entry_count"] = entry_count
            
            entry_offsets = list()
            for i in range(entry_count):
                entry_offsets.append(struct.unpack("<I", dec_et_section_2[(i*4)+4:(i*4)+8])[0])
            # print(f"entry_offsets: {entry_offsets}")
            
            et_resource_dict_1 = dict()
            et_resource_dict_2 = dict()
            i = 0
            while True:
                if i == entry_count:
                    break
                if i == entry_count -1:
                    et_resource = dec_et_section_2[entry_offsets[i]:]
                else:
                    et_resource = dec_et_section_2[entry_offsets[i]:entry_offsets[i+1]]
                # print()
                # print(et_resource)
                
                detection_path_end = et_resource.find(b'\x00\x00\x00')
                detection_path_end += 3
                
                detection_path = et_resource[:detection_path_end].decode('utf-16').rstrip('\x00')
                # print(f'detection_path: {detection_path}')
                et_resource_dict_1["target_file_path_1"] = detection_path
                field_count_end = detection_path_end+2
                field_count = struct.unpack('<H', et_resource[detection_path_end:field_count_end])[0]
                # print(f'field_count: {field_count}')
                
                detection_type_offset = et_resource[field_count_end:].find(b'\x00')
                detection_type_end = field_count_end + detection_type_offset
                
                while et_resource[detection_type_end] == 0: # 뒤에 0 padding 없애기
                    detection_type_end += 1
                
                detection_type = et_resource[field_count_end:detection_type_end].decode().rstrip('\x00')
                # print(f'detection_type: {detection_type}')
                et_resource_field = et_resource[detection_type_end:]
                
                # print(f'et_resource_field: {et_resource_field}')
                
                field_idx = 0
                for _ in range(field_count):
                    size = struct.unpack("<H", et_resource_field[field_idx:field_idx+2])[0]
                    tmp = struct.unpack("<H", et_resource_field[field_idx+2:field_idx+4])[0]
                    field_type = tmp >> 12 # 안 씀
                    field_identifier = tmp & 0x0FFF
                    # print(f'size: {size}\nfield_type: {field_type}\nfield_identifier: {field_identifier}')
                    # print(FIELD_IDENTIFIER.get(field_identifier, 'Unknown'))
                    # print(et_resource_field[field_idx+4:field_idx+4+size])
                    
                    if field_identifier == 2:
                        et_resource_dict_1['RD_file_name'] = et_resource_field[field_idx+4:field_idx+4+size].hex() # 빅엔디언 hex값으로 출력
                    elif field_identifier == 0xC:
                        et_resource_dict_1['target_file_path_2'] = et_resource_field[field_idx+4:field_idx+4+size].decode('utf-16').rstrip('\x00')
                    elif field_identifier == 0xF:
                        et_resource_dict_1['C_time'] = convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    elif field_identifier == 0x10:
                        et_resource_dict_1['A_time'] = convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    elif field_identifier == 0x11:
                        et_resource_dict_1['M_time'] = convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    
                    field_idx += size + 4
                    et_resource_dict_2[i] = et_resource_dict_1
                i += 1
                

            et_dict["threat_infomation"] = et_resource_dict_2
            # print(et_dict)
            print(path+r"\decrypted\\"+file_name+"_parsed.json")
            with open(path+r"\decrypted\\"+file_name+"_parsed.json", 'w') as f3:
                json.dump(et_dict, f3, indent=4)
            # print(file_list)
            
            for i in range(et_dict['entry_count']):
                D_time = int(et_dict['ditection_time'])
                M_time = int(et_dict['threat_infomation'][i]['M_time'])
                C_time = int(et_dict['threat_infomation'][i]['C_time'])
                # if not M_time < C_time:
                #     print(f'M_time - C_time: {M_time - C_time}')
                #     if not (M_time == C_time or (M_time - C_time) < 1000):
                #         print(f'D_time - M_time: {D_time - M_time}')
                #         if (D_time - M_time) < 1200000:
                #             print('yes')
                #         else:
                #             print('no')
                #     else:
                #         print('no')
                # else:
                #     print('no')
                
                if M_time < C_time:
                    print("복사 붙여넣기 or 드래그 & 드롭 or 압축")
                elif M_time == C_time or (M_time - C_time) < 1000:
                    print("인터넷")
                else:
                    print('정상 파일에 악성 시그니처 삽입')

                # elif (D_time - M_time) > 1200000:
                #     print('압축 or 잘라서 붙여넣기')
                
                print(D_time)
                print(et_dict['malware_name'])
                print(et_dict['threat_infomation'][i]['target_file_path_2'])
                print(M_time)
                print(et_dict['threat_infomation'][i]['A_time'])
                print(C_time)
                print(et_dict['threat_infomation'][i]['RD_file_name'])
                print()
            
            # if len(file_list) == 1:
            #     break
            
            
            # dec_et_section_1
            # dec_et_section_2
    
    # print(file_list)
    
    
    pass

def open_RD(path):
    # print(path)
    pass

def open_DH(path):
    # print(path)
    pass

def open_EV(path):
    # print(path)
    pass

def open_PF(path):
    # print(path)
    pass

import argparse
def arg_parser():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-o', type=str, help='Output Folder')
    # parser.add_argument('-mf', type=str, help='$MFT')
    parser.add_argument('-uj', type=str, help='$UsnJrnl')
    parser.add_argument('-df', type=str, help='Windows Defender Folder')
    # parser.add_argument('-ev', type=str, help='Event Log')
    # parser.add_argument('-pf', type=str, help='PF Folder')
    # parser.add_argument('-p', type=str, help='PF File')

    args = parser.parse_args()
    if args.o == None:
        print(r"You have to input Output Folder using '-o'")
        os._exit(0)
    # print(f'-mf: {args.mf}')
    # print(f'-uj: {args.uj}')
    # print(f'-df: {args.df}')
    # print(f'-ev: {args.ev}')
    # print(f'-pf: {args.pf}')
    
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
                # tmp_S_list = [None] * 16
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
                # tmp_S_list = [None] * 16
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
    print(df)
    df.to_csv(f'{out_path}\\S_list.csv', index=False)
    



def main():
    # open_MFT()
    arg_parser()
    pass

if __name__ == "__main__":
    print(convert_time_to_int("2024-10-11 13:10:51.000"))
    # main()