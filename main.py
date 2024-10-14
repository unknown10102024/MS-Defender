import md_utils as mu
import UsnJnrl
import ET_File
import DH_File


def main():
    args = mu.arg_parser()
    N_list = UsnJnrl.parsing(args.uj, args.o)
    E_list = ET_File.parsing(args.df, args.o)
    D_list = DH_File.parsing(args.df, args.o)
    
    T_list = mu.combine_N_list_E_list(N_list=N_list, E_list=E_list)
    S_list = mu.combine_S_list_D_list(T_list=T_list, D_list=D_list)
    
    if len(S_list) == 0:
        print("Failure: No evidence of Defender abuse found.")
    else:
        mu.save_S_list_to_csv(S_list, args.o)
        print("Success: Evidence of Defender abuse found.")
    
if __name__ == "__main__":
    main()
    

