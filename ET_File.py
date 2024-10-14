import md_utils as mu
import RD_File
import struct
import json
import os
import re

def parsing(path, out_path):
    
    ET_File_path = path + r"\Quarantine\Entries"
    et_dict = dict()
    # print(path)
    uid_pattern = r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    file_list = list()
    E_list = list()
    os.makedirs(out_path+r"\ET File decrypted", exist_ok=True)
    os.makedirs(out_path+r"\ET File parsed", exist_ok=True)
    for file_name in os.listdir(ET_File_path):
        file_path = os.path.join(ET_File_path, file_name)
        
        if re.match(uid_pattern, file_name) and os.path.isfile(file_path):
            file_list.append(file_name)
            with open(file_path, 'rb') as f1:
                et_header = f1.read(0x3C)
                rc4 = mu.RC4Variant()
                dec_et_header = rc4.process(et_header)
                # print(dec_et_header)
                et_section_1_len = struct.unpack('<I', dec_et_header[0x28:0x2C])[0]
                et_section_2_len = struct.unpack('<I', dec_et_header[0x2C:0x30])[0]
                et_section_1 = f1.read(et_section_1_len)
                et_section_2 = f1.read(et_section_2_len)
                rc4 = mu.RC4Variant()
                dec_et_section_1 = rc4.process(et_section_1)
                rc4 = mu.RC4Variant()
                dec_et_section_2 = rc4.process(et_section_2)
            
            with open(out_path+r"\ET File decrypted\\"+file_name+"_dec", 'wb') as f2:
                f2.write(dec_et_header+dec_et_section_1+dec_et_section_2)
            
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
            print(timestamp.hex())
            et_dict["ditection_time"] = mu.convert_filetime_to_datetime(timestamp)
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
                        et_resource_dict_1['C_time'] = mu.convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    elif field_identifier == 0x10:
                        et_resource_dict_1['A_time'] = mu.convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    elif field_identifier == 0x11:
                        et_resource_dict_1['M_time'] = mu.convert_filetime_to_datetime(et_resource_field[field_idx+4:field_idx+4+size])
                    
                    field_idx += size + 4
                    et_resource_dict_2[i] = et_resource_dict_1
                i += 1
                

            et_dict["threat_infomation"] = et_resource_dict_2
            # print(et_dict)
            # print(out_path+r"\ET File parsed\\"+file_name+"_parsed.json")
            with open(out_path+r"\ET File parsed\\"+file_name+"_parsed.json", 'w') as f3:
                json.dump(et_dict, f3, indent=4)
            # print(file_list)
            
            for i in range(et_dict['entry_count']):
                D_time = et_dict['ditection_time']
                M_name = et_dict['malware_name']
                F_path = et_dict['threat_infomation'][i]['target_file_path_2']
                M_time = et_dict['threat_infomation'][i]['M_time']
                A_time = et_dict['threat_infomation'][i]['A_time']
                C_time = et_dict['threat_infomation'][i]['C_time']
                RD_File_name = et_dict['threat_infomation'][i]['RD_file_name']
                int_M_time = mu.convert_time_to_int(M_time)
                int_C_time = mu.convert_time_to_int(C_time)
                if int_M_time < int_C_time:
                    # print("복사 붙여넣기 or 드래그 & 드롭 or 압축")
                    pass
                elif int_M_time == int_C_time or (int_M_time - int_C_time) < 1000:
                    # print("인터넷")
                    pass
                else:
                    # print('정상 파일에 악성 시그니처 삽입')
                    RD_File_path = path + r"\Quarantine\ResourceData" + '\\' + RD_File_name[:2] + '\\' + RD_File_name
                    # print("RD_File_path", RD_File_path)
                    
                    RD_File_size = RD_File.decrypting(RD_File_path, out_path)
                    
                    # print(D_time)
                    # print(M_name)
                    # print(F_path)
                    # print(M_time)
                    # print(A_time)
                    # print(C_time)
                    # print(RD_File_name)
                    # print()
                    tmp_E_list = [None] * 16
                    tmp_E_list[2] = F_path[2:]
                    tmp_E_list[3] = RD_File_size
                    tmp_E_list[4] = 'O' if RD_File_size else None
                    tmp_E_list[5] = M_name
                    tmp_E_list[6] = M_time
                    tmp_E_list[7] = A_time
                    tmp_E_list[8] = C_time
                    tmp_E_list[11] = D_time
                    tmp_E_list[12] = 'E'
                    tmp_E_list[13] = file_name
                    tmp_E_list[14] = RD_File_name
                    E_list.append(tmp_E_list)
            

    # print(E_list)
    return E_list
    # return out_path+r"\ET File parsed"
    
    