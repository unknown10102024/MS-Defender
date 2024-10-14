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
    D_list = DH_File.parsing(args.df, args.o) # out_path+r"\DH File decrypted"
    
    # print(N_list)
    # print(E_list)
    # print(D_list)
    
    T_list = mu.combine_N_list_E_list(N_list=N_list, E_list=E_list)
    S_list = mu.combine_S_list_D_list(T_list=T_list, D_list=D_list)

    print()
    print("--------------------------------------------------------------------------------")
    print(S_list)

    mu.save_S_list_to_csv(S_list, args.o)
    # pass

if __name__ == "__main__":
    main()

    # a = [0, 1, 2, 3, 4]
    # print(a[2])
    # del a[2]
    # print(a[2])
