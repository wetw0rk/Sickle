# Sickle Documentation

Currently the API used by modules is not documented. The source code is the official source of truth in terms of documentation. Since I'm actively working on new modules, the API is subject to change. Ultimately, the goal is to create official documentation for core API functions and make API as easy to use as possible.

Hopefully this will be complete in the next major release.

# Table of Contents

- [Linux Installation](#linux-installation)
- [Windows Installation](#windows-installation)

# Linux Installation

TODO

# Windows Installation

After Python has been installed, Windows installation is just as easy as installion on Linux. First clone the repository.

```
C:\>git clone https://github.com/wetw0rk/Sickle.git
Cloning into 'Sickle'...
remote: Enumerating objects: 531, done.
remote: Counting objects: 100% (91/91), done.
remote: Compressing objects: 100% (67/67), done.
remote: Total 531 (delta 22), reused 84 (delta 20), pack-reused 440
Receiving objects: 100% (531/531), 161.92 MiB | 1.32 MiB/s, done.
Resolving deltas: 100% (249/249), done.
Updating files: 100% (65/65), done.
```

Once cloned enter the `Sickle` directory and install the requirements using `pip3`.

```
C:\Sickle>pip3 install -r requirements.txt
DEPRECATION: Loading egg at c:\users\developer\appdata\local\programs\python\python312\lib\site-packages\sickle-2.0.2-py3.12.egg is deprecated. pip 24.3 will enforce this behaviour change. A possible replacement is to use pip for package installation.. Discussion can be found at https://github.com/pypa/pip/issues/12330
Collecting capstone>=3.0.5 (from -r requirements.txt (line 1))
  Using cached capstone-5.0.1-py3-none-win_amd64.whl.metadata (3.5 kB)
Collecting setuptools (from -r requirements.txt (line 2))
  Downloading setuptools-71.0.4-py3-none-any.whl.metadata (6.5 kB)
Using cached capstone-5.0.1-py3-none-win_amd64.whl (1.3 MB)
Downloading setuptools-71.0.4-py3-none-any.whl (2.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 9.3 MB/s eta 0:00:00
Installing collected packages: setuptools, capstone
Successfully installed capstone-5.0.1 setuptools-71.0.4

[notice] A new release of pip is available: 24.0 -> 24.1.2
[notice] To update, run: python.exe -m pip install --upgrade pip
```

Once dependencies have been installed simply run `setup.py` as shown below.

```
C:\Sickle>python setup.py install
running install
```

The last step is to enable ANSI colors. To do this simply double click the `enable-ansi.reg` located in the **documentation** folder within the repository. Upon comletion, if everything went well, you should be able to run sickle from anywhere.

```
C:\>sickle -h
usage: sickle [-h] [-r READ] [-f FORMAT] [-m MODULE] [-a ARCH] [-b BADCHARS] [-v VARNAME] [-i] [-l]

Sickle - Payload development framework

options:
  -h, --help                        Show this help message and exit
  -r READ, --read READ              Read bytes from binary file (use - for stdin)
  -f FORMAT, --format FORMAT        Output format (--list for more info)
  -m MODULE, --module MODULE        Development module
  -a ARCH, --arch ARCH              Select architecture for disassembly
  -b BADCHARS, --badchars BADCHARS  Bad characters to avoid in shellcode
  -v VARNAME, --varname VARNAME     Alternative variable name
  -i, --info                        Print detailed info for module or payload
  -l, --list                        List available formats, payloads, or modules
```