import md_utils as mu
import struct
import zipfile
import io
import os

def decrypting(path, out_path):
    ET_File_name = os.path.basename(path)
    # 암호화된 데이터를 입력 (복호화할 실제 데이터를 여기에 입력하세요)
    if not os.path.exists(path):
        return 0
    with open(path, 'rb') as f1:
        enc_data = f1.read()
        rc4 = mu.RC4Variant()
        dec_data = rc4.process(enc_data)
    
    section1_size = struct.unpack_from('<Q', dec_data, offset=8)[0]
    section2_size = struct.unpack_from('<Q', dec_data, offset=(section1_size + 0x1C))[0]
    # print(section2_size)
    data = dec_data[section1_size + 0x28:section1_size + section2_size + 0x28]

    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # 압축 파일에 데이터를 추가합니다
        zip_file.writestr(ET_File_name+"_dec", data)

    os.makedirs(out_path+r"\RD File decrypted", exist_ok=True)
    
    with open(out_path+r"\RD File decrypted\\" + ET_File_name+"_dec.zip", 'wb') as f2:
        f2.write(zip_buffer.getvalue())

    return section2_size

if __name__ == "__main__":
    path = r"C:\Users\fdno5\Desktop\MD\test artifact 1\Windows Defender\Quarantine\ResourceData\D9\D9B76D3FF2A4007AC09FD51D41820E9E49ED4B22"
    decrypting(path)