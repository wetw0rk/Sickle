#!/usr/bin/env python3
#
# 
# Script name : run_tests.py
#
# Description:
#   Run tests on non-interative modules
#

import os
import sys
import time

SICKLE_PATH = f"{os.path.dirname(__file__)}/../src"

IGNORE = ['__init__.py', "__pycache__"]

SLEEP_TIME = 0

MODULE_TESTS = \
{
    "diff": [f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=hexdump",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=hexdump",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=byte",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=byte",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=raw",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=raw",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=asm",
             f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=asm"],

    "badchar": [f"python3 -B {SICKLE_PATH}/sickle.py -m badchar -f c"],

    "disassemble": [f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -m disassemble -r generic_sc"],

    "pinpoint": [f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f c",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f cs",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f bash",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f java",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f nasm",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f perl",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f ruby",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f python",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f python3",
                 f"python3 -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f powershell"]
}

def get_clean_module_list(path):
    modules = os.listdir(path)

    exclude_list = []
    for i in range(len(modules)):
        if (modules[i] in IGNORE):
            exclude_list.append(modules[i])

    for i in range(len(exclude_list)):
        modules.remove(exclude_list[i])

    for i in range(len(modules)):
        modules[i] = modules[i][:-3]

    return modules

def execute_test(test):
    print(f"[*] Executing `{test}`\n")
    os.system(test)
    sys.stdout.write('\n')
    time.sleep(SLEEP_TIME)
    return

def test_all_help_pages():
    modules = get_clean_module_list(f"{SICKLE_PATH}/sickle/modules")

    help_pages = [f"python3 -B {SICKLE_PATH}/sickle.py -l",
                  f"python3 -B {SICKLE_PATH}/sickle.py -h",
                  f"python3 -B {SICKLE_PATH}/sickle.py"]

    for i in range(len(help_pages)):
        execute_test(help_pages[i])
        time.sleep(SLEEP_TIME)

    for i in range(len(modules)):
        test = f"python3 -B {SICKLE_PATH}/sickle.py -m {modules[i]} -i"
        execute_test(test)
        time.sleep(SLEEP_TIME)

    return

def test_all_formats():
    formats = get_clean_module_list(f"{SICKLE_PATH}/sickle/formats")
    
    for i in range(len(formats)):
        test = f"python3 -B {SICKLE_PATH}/sickle.py -r generic_sc -f {formats[i]} -b \"\\x00\\x0a\\x0d\""
        execute_test(test)

    return

def test_modules():
    for module, commands in MODULE_TESTS.items():
        print(f"[*] Testing {module} module")
        for i in range(len(commands)):
            execute_test(commands[i])
    return

def test_flag_errors():
    test_cases = [f"python3 -B {SICKLE_PATH}/sickle.py -r poop -f c", # Read from non-existing file
                  f"python3 -B {SICKLE_PATH}/sickle.py -r generic_sc -f poop", # Use invalid format
                  f"python3 -B {SICKLE_PATH}/sickle.py -a x80-6 -m disassemble -r generic_sc -f c", # Invalid arch
                  f"python3 -B {SICKLE_PATH}/sickle.py -m doeverything4me", # Invalid module
    ]

    for i in range(len(test_cases)):
        execute_test(test_cases[i])
        time.sleep(SLEEP_TIME)

def main():
    test_all_help_pages()
    test_all_formats()
    test_modules()
    test_flag_errors()

main()
