#!/usr/bin/env python3
"""
# Author : Khalid Maina
# Date : 01/07/2021

.............................................................................................................................
TheFHUNTER
__________

TheFHunter.py is a script that recursively searches a files by formats, unigue words or by names in a directory or directories.
If TheFHunter.py finds a files, it will execute the payload given to it such as to delete found files, encrypt found files, zip found files,
count found files, move and copy the found files to other directory.
It also contains decryption and unzipping features that can be used barely on a single file.
As for counting files, the result can be saved in csv format.

DISCLAIMER
__________

This script is meant to be used for research, educational purpose and to facilitate working with thousands of files that are in different directories.
As such, do not use it for malicious activities.
.............................................................................................................................
"""

import argparse
import os
import sys
import re
import time
import termcolor
import hashlib
import shutil
import pandas
import csv
import pyzipper
import pyAesCrypt
from concurrent.futures import ThreadPoolExecutor

target_files = []
banner = """
    TheFHunter
    _______________________________________
    Let's hunt them down...
        Don't worry, i mean the files.
                   ((((((-:-))))))
    _______________________________________
    version 1.0
"""


def search_by_format(file, formats):
    """Searches file by formats."""
    for format in formats:
        __, ext = os.path.splitext(file)
        if ext[1:] == format:
            return True


def search_by_name(file, names, march_all = False):
    """Searches file by name or a unigue word."""
    for name in names:
        if march_all:
            if name == file:
                return True
        else:
            regex = re.compile(r''+name+'')
            is_marched = regex.search(file)
            if is_marched:
                return True


def delete_file(files):
    """Deletes file."""
    for file in files:
        file_name = os.path.basename(file)
        try:
            os.remove(file)
            termcolor.cprint('[+] {} has been deleted.'.format(file_name), 'green')
        except PermissionError:
            termcolor.cprint("[-] Can't delete {}.Permission denied".format(file_name), 'red')
            continue
    return True


def move_file(files):
    """Moves file to a given directory."""
    move_path = input("[+] Enter the destination path : ")
    try:
        is_existed = os.path.exists(move_path)
        if not is_existed:
            raise FileNotFoundError
        if os.path.isfile(move_path):
            raise NotADirectoryError
        contents = os.listdir(move_path)
        for file in files:
            file_name = os.path.basename(file)
            try:
                if file_name in contents:
                    continue
                shutil.move(file, move_path)
                termcolor.cprint('[+] {} has been moved to {}.'.format(file_name, move_path), 'green')
            except PermissionError:
                termcolor.cprint("[-] Can't move {} to {}.Permission denied".format(file_name, move_path), 'red')
                continue
    except FileNotFoundError:
        termcolor.cprint('[-] {} does not exist.'.format(move_path), 'red')
        sys.exit()
    except NotADirectoryError:
        termcolor.cprint('[-] {} is a file.Directory is expected.'.format(move_path), 'red')
        sys.exit()
    return True


def copy_file(files):
    """Copies file to a given directory."""
    copy_path = input("[+] Enter the destination path : ")
    try:
        is_existed = os.path.exists(copy_path)
        if not is_existed:
            raise FileNotFoundError
        if os.path.isfile(copy_path):
            raise NotADirectoryError
        contents = os.listdir(copy_path)
        for file in files:
            file_name = os.path.basename(file)
            try:
                if file_name in contents:
                    continue
                shutil.copy(file, copy_path)
                termcolor.cprint('[+] {} has been copied to {}.'.format(file_name, copy_path), 'green')
            except PermissionError:
                termcolor.cprint("[-] Can't copy {} to {}.Permission denied".format(file_name, copy_path), 'red')
                continue
            except shutil.Error:
                continue
    except FileNotFoundError:
        termcolor.cprint('[-] {} does not exist.'.format(copy_path), 'red')
        sys.exit()
    except NotADirectoryError:
        termcolor.cprint('[-] {} is a file.Directory is expected.'.format(copy_path), 'red')
        sys.exit()
    return True


def encrypt_file(files):
    """Encrypts file with a given password and deletes it if needed."""
    buffer_size = 64 * 1024
    password = input("Enter your password : ")
    hash_password = hashlib.sha256(password.encode()).hexdigest()   #Converts text passsword to sha256 hashes
    for file in files:
        file_name = os.path.basename(file)
        encrypted_name = file + '.aes'  #Adds .aes format to an encrypted file
        try:
            pyAesCrypt.encryptFile(file, encrypted_name, hash_password, buffer_size)
            termcolor.cprint('[+] {} has been encrypted to {}.'.format(file_name, file_name + '.aes'), 'green')
        except PermissionError:
            termcolor.cprint("[-] Can't encrypt {}.Permission denied".format(file_name), 'red')
            continue
    option = input("[+] Do you want to delete the original files after been encrypted (yes/no)? : ")
    if option.lower() == 'yes':
        delete_file(files)  #Deletes a files.
    print()
    termcolor.cprint("[+] All files have been encrypted with password {}.Save the password for decryption purpose.".format(hash_password), 'blue')
    print()


def zip_file(files):
    """Zips a files."""
    zip_path = 'result.zip'
    try:
        with pyzipper.ZipFile(zip_path, 'w') as zf:
            for file in files:
                file_name = os.path.basename(file)
                zf.write(file)
                try:
                    termcolor.cprint('[+] {} has been added to {}.'.format(file_name, zip_path), 'green')
                except PermissionError:
                    termcolor.cprint("[-] Can't zip {}.Permission denied".format(file_name), 'red')
                    continue
    except Exception:
        raise
    return True


def write_csv(data, file):
    """Writes data to an csv file."""
    try:
        with open(file, 'w') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerows(data)
    except Exception:
        raise


def count_file(files):
    """Counts files by format and saves the result in csv file if needed."""
    dict_total = {}
    for file in files:
        file_name = os.path.basename(file)
        if not '.' in file_name or file_name.startswith('.'):
           dict_total[file_name] = 1
           continue
        __, ext = os.path.splitext(file_name)
        dict_total[ext] = dict_total.get(ext, 0) + 1 #Adds format and increments the total by 1.
    data = list(dict_total.items()) #converts it so as to fit pandas and csv.
    df = pandas.DataFrame(data, columns = ['Formats', 'Totals'])
    df.index = df.index + 1
    print()
    termcolor.cprint('[+] results', 'blue')
    print(df)
    termcolor.cprint('[+] Total files {}'.format(len(files)), 'green')
    print()
    option = input("Do you want to save the file to csv (yes/no)? :")
    if option == 'yes':
        write_csv(data, 'result.csv')
        termcolor.cprint("result has been written to result.csv.", 'green')


def run_payload(files, payload_type):
    """Runs a payload."""
    if not payload_type:
        return files
    if payload_type == 'delete':
        delete_file(files)
    elif payload_type == 'move':
        move_file(files)
    elif payload_type == 'copy':
        copy_file(files)
    elif payload_type == 'encrypt':
        encrypt_file(files)
    elif payload_type == 'zip':
        zip_file(files)
    elif payload_type == 'count':
        count_file(files)


def decrypt_file(file, password):
    """Decrypts file with a given password."""
    buffer_size = 64 * 1024
    try:
        is_existed = os.path.exists(file)
        if not is_existed:
            raise FileNotFoundError
        if os.path.isdir(file):
            raise IsADirectoryError
        if not file.endswith('.aes'):
            raise NameError
        file_name = os.path.basename(file)
        decrypted_name = file_name.replace('.aes', '')
        decrypted_path = os.path.join(os.path.dirname(file), decrypted_name)
        pyAesCrypt.decryptFile(file, decrypted_path, password, buffer_size)
        termcolor.cprint('[+] {} has been decrypted to {}.'.format(file_name, decrypted_name), 'green')
    except FileNotFoundError:
        termcolor.cprint('[-] {} does not exist.'.format(file), 'red')
    except IsADirectoryError:
        termcolor.cprint('[-] {} is a directory.File is expected.'.format(file), 'red')
    except NameError as e:
        termcolor.cprint("[-] {} is not an aes file.".format(file), 'red')
    except ValueError:
        termcolor.cprint("[-] {} can't be decrypted.Pasword Incorrect!.".format(file), 'red')
    except PermissionError:
        termcolor.cprint("[-] Can't decrypt {}.Permission denied".format(file_name), 'red')
    finally:
        print("Done.")
        sys.exit()


def unzip_file(file):
    """Unzips a zip file."""
    try:
        is_existed = os.path.exists(file)
        if not is_existed:
            raise FileNotFoundError
        if os.path.isdir(file):
            raise IsADirectoryError
        if not file.endswith('.zip'):
            raise NameError
        with pyzipper.ZipFile(file) as zf:
            zf.extractall()
        termcolor.cprint('[+] {} has been unzipped.'.format(file), 'green')
    except FileNotFoundError:
        termcolor.cprint('[-] {} does not exist.'.format(file), 'red')
    except IsADirectoryError:
        termcolor.cprint('[-] {} is a directory.File is expected.'.format(file), 'red')
    except NameError:
        termcolor.cprint("[-] {} is not a zip file.".format(file), 'red')
    except PermissionError:
        termcolor.cprint("[-] Can't unzip {}.Permission denied".format(file_name), 'red')
    except RuntimeError:
        termcolor.cprint("[-] Can't unzip {}.File is encrypted".format(file_name), 'red')
    finally:
        print("Done.")
        sys.exit()


def hunt_file(directory, search_type, regexs, stop_on_success, executor, verbose):
    """Searches a list of regexs(formats or files name) in a directory and adds the march to the target_files list.
    directory : Directory to be searched.
    search_type : Type of search to be performed.It could be by format, name, or by word.
    regex : List of a target formats, file names or unigue words.
    stop_on_success : If specified, the script will terminates as soon as it finds the march.
    executor : threadpoolexecutor objects.
    verbose : verbosity.
    """
    global target_files, permission_denied_directorie
    try:
        is_existed = os.path.exists(directory)
        if not is_existed:
            raise FileNotFoundError
        if os.path.isfile(directory):
            raise NotADirectoryError
        try:
            contents = os.listdir(directory) #list content of a directory
        except PermissionError:
            termcolor.cprint("[-] Permission denied : You don't have enough privilege to open this directory {}".format(directory), 'red')
            return
        if verbose:
            termcolor.cprint("[+] in {}".format(directory), 'blue')
        for content in contents:
            abspath = os.path.join(directory, content)
            if os.path.isdir(abspath):
                #if content is directory, it calls itself.
                hunt_file(abspath, search_type, regexs, stop_on_success, executor, verbose)
            else:
                if search_type == 'name':
                    #search by name.
                    is_marched = search_by_name(content, regexs, True)
                elif search_type == 'word':
                    #search by word.
                    is_marched = search_by_name(content, regexs)
                elif search_type == 'format':
                    #search by format.
                    is_marched = search_by_format(content, regexs)
                elif search_type == 'All':
                    #search by all files
                    target_files.append(abspath)
                    continue
                if is_marched and stop_on_success:
                    target_files.append(abspath)    #Adds to target_files list.
                    executor.shutdown(wait = True)  #terminates the threadpoolexecutor.
                    return
                elif is_marched and not stop_on_success:
                    target_files.append(abspath)    #Adds to target_files list.
                else:
                    if verbose >= 2:
                        print(content)
    except FileNotFoundError:
        termcolor.cprint('[-] {} does not exist.'.format(directory), 'red')
        sys.exit()
    except NotADirectoryError:
        termcolor.cprint('[-] {} is a file.Directory is expected.'.format(directory), 'red')
        sys.exit()
    return True


def main():
    termcolor.cprint(banner, 'blue')
    time.sleep(1)
    print()
    parser = argparse.ArgumentParser(prog = 'TheFHunter', description = "TheFHunter.py is a script that recursively searches a file or files by format, word or by name in a directory or directories.If TheFHunter.py finds a files, it will perform an action given to it such as deleting files, encrypting files, zipping files, counting files, moving and copying files to other directory.As for counting files, the result can be saved in csv format.", usage = '%(prog)s [options]')
    parser.add_argument('-d', nargs = '*', default = [os.getcwd()], type = str, help = 'Target directory or directories path.', metavar = 'directory', dest = 'directory')
    parser.add_argument('-f', '--formats', nargs = '+', dest = 'format', metavar = 'Format', type = str, help = 'Searches file or files by their formats.')
    parser.add_argument('-n', '--name', nargs = '+', dest = 'name', metavar = 'name', type = str, help = 'Searches file or files by their name .')
    parser.add_argument('-w', '--word', nargs = '+', dest = 'word', metavar = 'word', type = str, help = 'Searches file or files by their word .')
    parser.add_argument('-p', '--payload', choices = ['delete', 'encrypt', 'move', 'copy', 'zip', 'count'], dest = 'payload', help = 'payload to be run when files are found.')
    parser.add_argument('-S', '--stop-on-success', action = 'store_true', dest = 'stop_on_success', help = 'Terminates as soon as it finds one that marches.')
    parser.add_argument('--version', action = 'version', version = 'version 1.0', help = 'Prints the current version.')
    parser.add_argument('-v', '--verbose', action = 'count', default = 0, help = 'Increases verbosity.')
    parser.add_argument('--decrypt', nargs = 2, dest = 'decrypt', help = 'Decrypts an encrypted file. e.g --decrypt [file path] [password]')
    parser.add_argument('--unzip', dest = 'unzip', help = 'Unzips a zip file.')
    args = parser.parse_args()
    if args.decrypt:
        file = args.decrypt[0]
        password = args.decrypt[1]
        decrypt_file(file, password)
    if args.unzip:
        unzip_file(args.unzip)
    if args.name:
        search_type = 'name'
        regexs = args.name
    elif args.word:
        search_type = 'word'
        regexs = args.word
    elif not args.format:
        search_type = 'All'
        regexs = 'all'
    elif args.format:
        search_type = 'format'
        regexs = args.format
    with ThreadPoolExecutor() as executor:
        for directory in args.directory:
            task = executor.submit(hunt_file, directory, search_type, regexs, args.stop_on_success, executor, args.verbose)
        executor.shutdown(wait = True)
    if target_files:
        for file in target_files:
            termcolor.cprint("[+] Found {}.".format(file), 'green')
        print()
        run_payload(target_files, args.payload)
    else:
        termcolor.cprint("[-] Files not found.", 'red')
    print('Done.')


if __name__ == '__main__':
    main()
