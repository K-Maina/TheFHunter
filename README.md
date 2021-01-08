# TheFHunter

>   TheFHunter

    _______________________________________

    Let's hunt them down...

        Don't worry, i mean the files.

                   ((((((-:-))))))

    _______________________________________

    version 1.0

**TheFHunter.py** is a script that recursively searches a files by formats, unigue words or by names in a directory or directories.If the script finds the correct files, it will execute the payload given to it such as to delete found files, encrypt found files, zip found files,
count found files, move and copy the found files to other directory.It also contains decryption and unzipping features that can be used barely on a single file.As for counting files, the result can be saved in csv format.

# SETUP
1. Install python 3.
2. Install pip3
3. Clone the repo :-
```
git clone https://github.com/K-Maina/TheFHunter.git
```
4. Navigate to the directory of the scripts :-
```
cd [directory path]
```
5. Run setup.py script :-
```
python setup.py
```
6. Run TheFHunter.py :-
```
python TheFHunter.py
```

*Note : As for setup.py, You can manually install the packages by running `pip3 install [package name]` or `pip install [package name]`*

# DEPENDENCIES

* Python 3.4 and above.
* modules
  * argparse
  * os
  * sys
  * re
  * time
  * termcolor
  * hashlib
  * shutil
  * pandas
  * csv
  * pyzipper
  * pyAesCrypt
  * concurrent

# PLATFORM DEPENDENCY

* It supports *all platforms*

# TUTORIAL
* To search all files in the current working directory :-
```
python TheFHunter.py
```
* To search files in a directory :-
```
python TheFHunter.py -d [directory path]
```
* You can search files in multiple directories :-
```
python TheFHunter.py -d [directory path1] [directory path2] ...
```
* To search files by formats :-
```
python TheFHunter.py -d [directory path] -f [format]
```
* You can search files with multiple formats :-
```
python TheFHunter.py -d [directory path] -f [format1] [format2] [format3] ...
```
* To search files by a unique words :-
```
python TheFHunter.py -d [directory path] -w [unigue word1] [unigue word2] ...
```
* To search files by their name :-
```
python TheFHunter.py -d [directory path] -n [name1] [name2] ...
```
* You can delete the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p delete
```
* You can encrypt the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p encrypt
```
* You can move the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p move
```
* You can copy the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p copy
```
* You can zip the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p zip
```
* You can count the found files :-
```
python TheFHunter.py -d [directory path] -f [format] -p count
```
* You can decrypt an encrypted file :-
```
python TheFHunter.py --decrypt [file path] [password]
```
* You can unzip a zipped file :-
```
python TheFHunter.py --unzip [file path]
```
*Note : As for search by format, the format must not include __'.'__.e.g :-*

**Correct :-**
```
python TheFHunter.py -d [directory path] -f pdf txt xlsx
```
**Incorrect :-**
```
python TheFHunter.py -d [directory path] -f .pdf .txt .xlsx
```

# DISCLAIMER

This script is meant to be used for research, educational purpose and to facilitate working with thousands of files that are in different directories.
As such, do not use it for **malicious activities**.
