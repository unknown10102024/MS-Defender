import md_utils as mu
import UsnJnrl
import ET_File
import RD_File
import DH_File
import pandas as pd


def main():
    args = mu.arg_parser()
    # oa.open_MFT(args.mf)
    N_list = UsnJnrl.parsing(args.uj, args.o)
    E_list = ET_File.parsing(args.df, args.o) # out_path+r"\ET File decrypted" out_path+r"\ET File parsed"
    DH_File_path = DH_File.parsing(args.df, args.o) # out_path+r"\DH File decrypted"
    print(N_list)
    print(E_list)
    
    S_list = list()
    N_list_len = len(N_list)
    E_list_len = len(E_list)
    N_idx = 0
    while N_idx < N_list_len:
        E_idx = 0
        while E_idx < E_list_len:
            if N_list[N_idx][2] == E_list[E_idx][2]: # compare F_path
                T_inject = mu.convert_time_to_int(N_list[N_idx][9]) # T_inject
                M_Time = mu.convert_time_to_int(E_list[E_idx][6]) # M_Time
                if abs(M_Time - T_inject) < 60000: # 1 minute 
                    tmp_S_list = [None, None, None, None, None, None, None, None, None, None, None, None, None]
                    tmp_S_list[0] = None
                    tmp_S_list[1] = None
                    tmp_S_list[2] = E_list[E_idx][2]
                    tmp_S_list[3] = None
                    tmp_S_list[4] = E_list[E_idx][4]
                    tmp_S_list[5] = E_list[E_idx][5]
                    tmp_S_list[6] = E_list[E_idx][6]
                    tmp_S_list[7] = E_list[E_idx][7]
                    tmp_S_list[8] = E_list[E_idx][8]
                    tmp_S_list[9] = N_list[N_idx][9]
                    tmp_S_list[10] = None
                    tmp_S_list[11] = E_list[E_idx][11]
                    tmp_S_list[12] = "N E"
                    S_list.append(tmp_S_list)
                    
                    del N_list[N_idx]
                    del E_list[E_idx]
                    
                    E_list_len -= 1
                    N_list_len -= 1
                    N_idx -= 1
                    
                    break
                    
            E_idx += 1
            
        N_idx += 1
    
    S_list.extend(N_list)
    S_list.extend(E_list)
    print()
    print("--------------------------------------------------------------------------------")
    print(S_list)
    

    columns = pd.MultiIndex.from_tuples([('Who', 'N_com'), ('Who', 'N_user'), ('What_file', 'F_path'), ('What_file', 'F_size'), ('What_file', 'F_enc'), ('What_sig', 'N_mal'), ('When_inject', 'M_time'), ('When_inject', 'A_time'), ('When_inject', 'C_time'), ('When_inject', 'T_inject'), ('How_inject', 'N_proc'), ('When_det_del', 'T_det_del'), ('Flag', 'flag')])

    # DataFrame 생성 및 출력
    df = pd.DataFrame(S_list, columns=columns)
                
    print(df)
    df.to_csv(f'{args.o}\\S_list.csv', index=False)
    
    
    # RD_File.parsing(args.df + r"\Quarantine\ResourceData")
    # oa.open_EV(args.ev)
    # oa.open_PF(args.pf)
    pass

if __name__ == "__main__":
    main()
    # a = [0, 1, 2, 3, 4]
    # print(a[2])
    # del a[2]
    # print(a[2])