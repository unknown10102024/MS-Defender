import json
import struct
import os
import re
from itertools import count



def dynamic_unpack(byte_size):
    if byte_size == 1:
        format_char = 'B'  # unsigned char (1 byte)
    elif byte_size == 2:
        format_char = 'H'  # unsigned short (2 bytes)
    elif byte_size == 4:
        format_char = 'I'  # unsigned int (4 bytes)
    elif byte_size == 8:
        format_char = 'Q'  # unsigned long long (8 bytes)
    else:
        raise ValueError("Unsupported byte size")
    
    return format_char
C_counter = count(0)
def parsing_mod_C(f, final_dict):
    length = struct.unpack("<I", f.read(4))[0]
    types = struct.unpack("<I", f.read(4))[0]
    if length % 8 != 0:
        length += 8 - (length % 8)
    result = f.read(length).decode('utf-16').rstrip('\x00')
    key_flag = next(C_counter)
    if key_flag == 0:
        final_dict["malware_name"] = result
    elif key_flag == 1: 
        final_dict["user"] = result
    elif key_flag == 2:
        final_dict["spawning_process_name"] = result
    elif key_flag == 3:
        final_dict["security_group"] = result
    
    # print(result)
    return result

def parsing_mod_B(f, length, block_dict):
    f.read(0x18)
    length -= 0x18 
    
    while True:
        if length < 8:
            f.read(length)
            break
        key_length = struct.unpack("<I", f.read(4))[0]
        key = f.read(key_length).decode('utf-16').rstrip('\x00')
        # print(key)
        
        value_length_types = struct.unpack("<I", f.read(4))[0]
        if value_length_types == 0x6:
            value_length = struct.unpack("<I", f.read(4))[0]
            value = f.read(value_length).decode('utf-16').rstrip('\x00')
            length -= 4 
        else:
            if value_length_types == 0x5:
                value_length = 0x1
            elif value_length_types == 0x4:
                value_length = 0x8
            elif value_length_types == 0x3:
                value_length = 0x4
            else:
                raise ValueError("Error in parsing_mod_B and find a velue that is", value_length_types)
            
            value = struct.unpack("<"+dynamic_unpack(value_length), f.read(value_length))[0]

        # print(value)
        block_dict[key] = value
        length -= (8 + key_length + value_length)

    return

A_counter = count(0)
def parsing_mod_A(f, rotation_number, final_dict):
    while True:
        if rotation_number <= 0:
            break
        rotation_number -= 1
        
        length = struct.unpack("<I", f.read(4))[0]
        types = struct.unpack("<I", f.read(4))[0]
        if length % 8 != 0:
            length += 8 - (length % 8)
        
        
        if types == 0x15:
            result = f.read(length).decode('utf-16').rstrip('\x00')
            # print(result)
            if 'file' in result or 'beha' in result or 'proc' in result:
                rotation_number -= 1
                length = struct.unpack("<I", f.read(4))[0]
                types = struct.unpack("<I", f.read(4))[0]
                if length % 8 != 0:
                    length += 8 - (length % 8)
                result = f.read(length).decode('utf-16').rstrip('\x00')
                final_dict["original_file_path"] = result
            else:
                key, value = result.split(':', 1)
                final_dict[key] = value
        elif types == 0x6:
            result = struct.unpack("<"+dynamic_unpack(length), f.read(length))[0]
            key_flag = next(A_counter)
            if key_flag == 0: 
                final_dict["quarantine_file_deletion_flag"] = result
            elif key_flag == 1: 
                final_dict["information_number"] = result
            
        elif types == 0x28:
            result = parsing_mod_B(f, length, final_dict)
        elif types == 0x1E:
            result = hex(struct.unpack("<I", f.read(4))[0])[2:].upper().zfill(8) + '-'
            result += hex(struct.unpack("<H", f.read(2))[0])[2:].upper().zfill(4) + '-'
            result += hex(struct.unpack("<H", f.read(2))[0])[2:].upper().zfill(4) + '-'
            result += hex(struct.unpack(">H", f.read(2))[0])[2:].upper().zfill(4) + '-'
            result += hex(struct.unpack(">H", f.read(2))[0])[2:].upper().zfill(4)
            result += hex(struct.unpack(">I", f.read(4))[0])[2:].upper().zfill(8)
            final_dict["ET_file_name"] = result
            
        else:
            result = f.read(length)
            
        # print(result)
        
            

    return result


def read_skip(f, rotation_number):
    for _ in range(rotation_number):
        length = struct.unpack("<I", f.read(4))[0]
        types = struct.unpack("<I", f.read(4))[0]
        if length % 8 != 0:
            length += 8 - (length % 8) 
        f.read(length)
    

def parsing(path, out_path):
    file_list = list()
    final_dict = dict()
    path += r"\Scans\History\Service\DetectionHistory"
    out_path = out_path+r"\DH File parsed"
    os.makedirs(out_path, exist_ok=True)
    guid_pattern = r"[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}"
    sub_folder_pattern = r"[A-F0-9]{2}"
    
    for sub_folder_name in os.listdir(path):
        if not (re.match(sub_folder_pattern, sub_folder_name) and os.path.isdir(path+'\\'+sub_folder_name)):
            continue
        for file_name in os.listdir(path+'\\'+sub_folder_name):
            file_path = os.path.join(path+'\\'+sub_folder_name, file_name)

            if re.match(guid_pattern, file_name) and os.path.isfile(file_path):
                # print(file_name)
                file_list.append(file_name)
                with open(file_path, 'rb') as f:
                    f.read(0x18) 
                    GUID = hex(struct.unpack("<I", f.read(4))[0])[2:].upper().zfill(8) + '-'
                    GUID += hex(struct.unpack("<H", f.read(2))[0])[2:].upper().zfill(4) + '-'
                    GUID += hex(struct.unpack("<H", f.read(2))[0])[2:].upper().zfill(4) + '-'
                    GUID += hex(struct.unpack(">H", f.read(2))[0])[2:].upper().zfill(4) + '-'
                    GUID += hex(struct.unpack(">H", f.read(2))[0])[2:].upper().zfill(4)
                    GUID += hex(struct.unpack(">I", f.read(4))[0])[2:].upper().zfill(8)
                    # print(GUID)
                    final_dict["DH_file_name"] = GUID
                    parsing_mod_A(f, 1, final_dict) 
                    
                    parsing_mod_C(f, final_dict)
                    
                    
                    read_skip(f, 5) 
                    
                    parsing_mod_A(f, 1, final_dict)
                    
                    read_skip(f, 4)
                    
                    info_num = parsing_mod_A(f, 1, final_dict) 
                    
                    chunk_dict = dict()
                    
                    idx = 0
                    while True:
                        if idx >= info_num:
                            break
                        
                        block_dict = dict()

                        parsing_mod_A(f, 1, block_dict)
                        
                        parsing_mod_A(f, 2, block_dict) 
                        
                        read_skip(f, 2) 

                        parsing_mod_A(f, 1, block_dict)
                        
                        chunk_dict[idx] = block_dict
                        
                        idx += 1
                    
                    final_dict["threat_infomation"] = chunk_dict

                    read_skip(f, 3)

                    parsing_mod_A(f, 1, final_dict) 

                    read_skip(f, 2)

                    parsing_mod_C(f, final_dict)

                    read_skip(f, 1)

                    parsing_mod_C(f, final_dict)

                    read_skip(f, 9)

                    parsing_mod_C(f, final_dict)
                    
                    with open(f"{out_path}\\{file_name}.json", 'w') as out:
                        json.dump(final_dict, out, indent=4)
    # print(out_path)
    return out_path



if __name__ == "__main__":
    path = r"C:\Users\fdno5\Desktop\Malwares\DC2943A4-8C68-4880-AA6D-0513A1B96A7C"
    path = r"C:\Users\fdno5\Desktop\Malwares 4\8304BF40-293A-40CB-A73B-16395F8927F4"
    path = r"C:\Users\fdno5\Desktop\Malwares 4\F3483C2F-6000-438E-ABE7-B1088ED36FA1"
    path = r"C:\Users\fdno5\Desktop\Malwares 4\D3FE516C-B807-4080-92DD-F6C6622D9621_low"
    parsing(path)
    
    
    