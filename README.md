# MSDAD (MS Defender Abuse Detector)
"MSDAD is a CLI tool that detects traces of completely removed file deletions (using zero-filling) by abusing MS Defender."


# Usage
python main.py -uj \<$UsnJrnl .db file path\> -df \<Defender folder path\> -o \<output folder path\>

### Options
-uj: Path to the .db file extracted using [NTFS Log Tracker 1.71](https://sites.google.com/site/forensicnote/ntfs-log-tracker?pli=1)

-df: Path to the Windows Defender folder(_\\ProgramData\\Microsoft\\Windows Defender_), already extracted using a tool like [FTK Imager](https://www.exterro.com/ftk-product-downloads/ftk-imager-version-4-7-1). 

-o: Path to the folder where results will be saved


### Example
python C:Tmp\MSDAD\main.py -uj "C:\artifact\parsed_usnjrnl_using_log_tracker.db" -df "C:\artifact\Windows Defender\" -o "C:\artifact\"


# Test Environment
The tool can be used on your own computer, but a ready-to-use VM image is also available for testing.

Both the VM image and the Windows password are set to "defender".

The VM contains pre-extracted artifacts needed for the tool’s use, stored in the "artifact" folder. Additionally, it includes tools such as a PowerShell script designed to inject malicious signatures to verify completely removed file deletions via Defender, as well as FTK, HxD, and others.

[Download link](https://drive.google.com/file/d/1gguPEA48V552HW5HNlvHHQ0ztBsXWCgH/view?usp=sharing)
