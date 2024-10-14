# MSDAD (MS Defender Abuse Detector)
MSDAD is a CLI tool that detects traces of completely removed file deletions (using zero-filling) by abusing MS Defender.


# Usage
python main.py -uj \<$UsnJrnl .db file path\> -df \<Defender folder path\> -o \<output folder path\>

### Options
-uj: Path to the .db file extracted using [NTFS Log Tracker 1.71](https://sites.google.com/site/forensicnote/ntfs-log-tracker?pli=1)

-df: Path to the Windows Defender folder(_\\ProgramData\\Microsoft\\Windows Defender_), already extracted using a tool like [FTK Imager](https://www.exterro.com/ftk-product-downloads/ftk-imager-version-4-7-1). 

-o: Path to the folder where results will be saved


#### Example
python C:\Tmp\MSDAD\main.py -uj "C:\Tmp\artifact\parsed_usnjrnl_using_log_tracker.db" -df "C:\Tmp\artifact\Windows Defender\" -o "C:\result folder\"

# Example

### Example of using MSDAD in CMD
![usageincmd](https://github.com/user-attachments/assets/48b17d00-8bce-402b-a7b5-b86f16b47301)


### Files parsed and extracted
![resultfolder](https://github.com/user-attachments/assets/a71e8565-c7c7-43a0-bebc-eea0235e8beb)

### Suspected files list (S List) extracted
![slist](https://github.com/user-attachments/assets/66399f94-6293-4fb7-957d-e7269363d53b)
  #### Description of S List Columns
  - who
    - N_com:     Computer name
    - N_user:    User name
  - What_file
    - F_path:    Pull-path of the target file
    - F_size:    Size of the target file
    - F_enc:     Encrypted data of the target file exists
  - What_sig
    - N_mal:     Malware information
  - When_inject
    - M_time:    Last Modified time of the target file
    - A_time:    Last accessed time of the target file
    - C_time:    Created time of the target file
    - T_inject:  Signature injection timestamp
  - How_inject
    - N_proc:    Last process executed the target file
  - When_det_del
    - T_det_del: Timestamp of the target file was detected and deleted
  - Used_artifacts
    - flag:      Initials of artifacts used to extract the suspected file EX) N = $Usnjrnl, E = ET File, D = DH File
    - N_ET_File: ET file name used to extract the suspected file
    - N_RD_File: RD file name extracted and mapped to the suspected file
    - N_DH_File: DT file name used to extract the suspected file

### Caution
When extracting the .db file from the $UsnJrnl using NTFS Log Tracker, ensure that the section highlighted in red is set to UTC-0, as shown in the image below.
![NTFS Log Tracker](https://github.com/user-attachments/assets/dfebe4a0-0e90-4b61-a5d8-676687a80bbd)


# Test Environment
The tool can be used on your own computer, but a ready-to-use VM image is also available for testing.

Both the VM image and the Windows password are set to "defender".

The VM contains pre-extracted artifacts needed for the tool’s use, stored in the "artifact" folder. Additionally, it includes tools such as a PowerShell script designed to inject malicious signatures to verify completely removed file deletions via Defender, as well as FTK, HxD, and others.

[Download link](https://drive.google.com/file/d/1gguPEA48V552HW5HNlvHHQ0ztBsXWCgH/view?usp=sharing)