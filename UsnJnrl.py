import sqlite3
import json

database = r"C:\Users\fdno5\Desktop\MD\test artifact 3\1\0_2024-10-05 19-22-57.db"
database = r"C:\Users\fdno5\Desktop\MD\test artifact 1\1_2024-10-04 19-42-17.db"

def parsing(path, out_path):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    target_string = "Basic_Info_Changed / Data_Overwritten / File_Closed / File_Deleted"

    cursor.execute("""
        SELECT *
        FROM UsnJrnl 
        WHERE Event = ?
    """, (target_string,))
    rows1 = cursor.fetchall()

    list_defender_del = []
    list_suspected = []
    for row1 in rows1:
        cursor.execute("""
        SELECT TimeStamp, Event
        FROM UsnJrnl 
        WHERE FullPath = ? AND FileReferenceNumber = ? AND ParentFileReferenceNumber = ?
        """, (row1[3], row1[8], row1[9],))
        rows2 = cursor.fetchall()
        rows2_timestamp = list(map(lambda x:x[0], rows2))
        rows2_event = list(map(lambda x:x[1], rows2))
        target_idx = rows2_event.index(target_string)
        if target_idx >= 3:
            if rows2_event[target_idx-1] == "Basic_Info_Changed / Data_Overwritten":
                if rows2_event[target_idx-2] == "Basic_Info_Changed":
                    list_defender_del.append(row1)
                    if "File_Created" not in rows2_event[target_idx-3] and any(keyword in rows2_event[target_idx-3] for keyword in ["Data_Overwritten", "Data_Added", "Data_Truncated"]):
                        list_suspected.append((list(row1) + [rows2_timestamp[target_idx-3]]))

    N_list = list()
    for row4 in list_suspected:
        tmp_N_list = [None, None, None, None, None, None, None, None, None, None, None, None, None]
        
        F_path = row4[3]
        T_inject = row4[-1]
        T_det_del = row4[1]
        tmp_N_list[2] = F_path
        tmp_N_list[9] = T_inject + r".000"
        tmp_N_list[11] = T_det_del + r".000"
        tmp_N_list[12] = 'N'
        N_list.append(tmp_N_list)
        # print([F_path, T_inject, T_det_del])
        
    cursor.close()
    conn.close()

    output_path = f"{out_path}\\usnjrnl_parsed.json"
    with open(output_path, 'w') as out:
        json.dump(N_list, out, indent=4)

    return N_list
    # return output_path
