#!/usr/bin/python3

import argparse
import json
import os
import random
import re
import string
import struct
from enum import Enum
from pathlib import Path



try:
    from enums.Architectures import Arch
    from enums.Compilers import Compiler
    from utils.utils import get_project_root

    base_directory = get_project_root()
    define_search_and_replace = False

except ModuleNotFoundError:
    def get_project_root() -> Path:
        return Path(__file__).parent


    base_directory = get_project_root()
    define_search_and_replace = True


    class Arch(Enum):
        Any = ""
        x86 = "x86"
        x64 = "x64"

        @staticmethod
        def from_string(label):
            if label.lower() in ["any", "all"]:
                return Arch.Any
            elif label.lower() in ["32", "86", "x86", "i386"]:
                return Arch.x86
            elif label.lower() in ["64", "x64", "amd64", "x86_64"]:
                return Arch.x64


    class Compiler(Enum):
        All = ""
        MSVC = "MSVC"
        MINGW = "MinGW"

        @staticmethod
        def from_string(label):
            if label.lower() in ["all"]:
                return Compiler.All
            elif label.lower() in ["msvc"]:
                return Compiler.MSVC
            elif label.lower() in ["mingw"]:
                return Compiler.MINGW

class SysWhispers(object):
    def __init__(
            self,
            arch: Arch = Arch.x64,
            compiler: Compiler = Compiler.MSVC,
            prefix: str = 'SWR7',):

        self.prefix = prefix
        self.arch = arch
        self.compiler = compiler
 


        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.typedefs: list = json.load(
            open(os.path.join(base_directory, 'data', 'typedefs.json')))
        self.prototypes: dict = json.load(
            open(os.path.join(base_directory, 'data', 'prototypes.json')))

        self.structured_types = []
        self.replaced_types = []


        self.includes = []
        self.already_defined_types = []
        self.already_defined_enums = []
   


    def generate(self, function_names: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        elif any([f not in self.prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Write C file.
        with open(os.path.join(base_directory, 'data', 'base.c'), 'rb') as base_source:
            with open(f'{basename}.c', 'wb') as output_source:
                base_source_contents = base_source.read().decode()

                base_source_contents = base_source_contents.replace('<BASENAME>', os.path.basename(basename), 1)
                base_source_contents = base_source_contents.replace('<NUMBER_FUNCTIONS>', str(len(function_names)), 1)
                

                syscall_init_contets=""
                for i in range(len(function_names)):
                    syscall_init_contets += "Syscall {} = ".format(function_names[i].replace(self.prefix,"ZW")) 
                    syscall_init_contets +="{"
                    syscall_init_contets += "{}".format(hex(self._get_function_hash(function_names[i])))
                    syscall_init_contets += ",{}".format(len(self.prototypes[function_names[i]]['params']))
                    syscall_init_contets +="};\n\t"
                    syscall_init_contets += "Syscalls[{}] = &{};\n\t".format(i,function_names[i].replace(self.prefix,"ZW"))
                 

                base_source_contents = base_source_contents.replace('<SYSCALL_DEFINE>', syscall_init_contets, 1)
                base_source_contents = base_source_contents.replace('<REPLACE_NTDLLDLL_HASH>', hex(self._get_function_hash("ntdll.dll")), 1)

                output_source.write(base_source_contents.encode())
          
        
                # Write the function define.
                for i in range(len(function_names)):
                    output_source.write((self._get_function_define(function_names[i],i) + '\n\n').encode())


        basename_suffix = ''
        basename_suffix = basename_suffix.capitalize() if os.path.basename(basename).istitle() else basename_suffix
        if self.compiler in [Compiler.All, Compiler.MSVC]:
            if self.arch in [Arch.Any, Arch.x64]:
                # Write x64 ASM file
                basename_suffix = f'_{basename_suffix}' if '_' in basename else basename_suffix
                with open(os.path.join(base_directory, 'data', 'base-x64.asm'), 'rb') as base_source:
                    with open(f'{basename}{basename_suffix}-asm.x64.asm', 'wb') as output_asm:
                        base_source_contents = base_source.read().decode()
                        output_asm.write(base_source_contents.encode())
  

            if self.arch in [Arch.Any, Arch.x86]:
                # Write x86 ASM file
                with open(os.path.join(base_directory, 'data', 'base-x86.asm'), 'rb') as base_source:
                    with open(f'{basename}{basename_suffix}-asm.x86.asm', 'wb') as output_asm:
                        base_source_contents = base_source.read().decode()
                        output_asm.write(base_source_contents.encode())

        if self.compiler in [Compiler.All, Compiler.MINGW]:
            if self.arch in [Arch.Any, Arch.x64]:
                # Write x64 ASM file
                basename_suffix = f'_{basename_suffix}' if '_' in basename else basename_suffix
                with open(os.path.join(base_directory, 'data', 'base-x64.s'), 'rb') as base_source:
                    with open(f'{basename}{basename_suffix}-asm.x64.s', 'wb') as output_asm:
                        base_source_contents = base_source.read().decode()
                        output_asm.write(base_source_contents.encode())
  

            if self.arch in [Arch.Any, Arch.x86]:
                # Write x86 ASM file
                with open(os.path.join(base_directory, 'data', 'base-x86.s'), 'rb') as base_source:
                    with open(f'{basename}{basename_suffix}-asm.x86.s', 'wb') as output_asm:
                        base_source_contents = base_source.read().decode()
                        output_asm.write(base_source_contents.encode())                

        # Write header file.
        with open(os.path.join(base_directory, 'data', 'base.h'), 'rb') as base_header:
            with open(f'{basename}.h', 'wb') as output_header:
                # Replace <SEED_VALUE> with a random seed.
                base_header_contents = base_header.read().decode()
                base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.seed:08X}', 1)

                # Write the base header.
                output_header.write(base_header_contents.encode())

                # Write the typedefs.
                for typedef in self._get_typedefs(function_names):
                    output_header.write(typedef.encode() + b'\n\n')

                # Write the function prototypes.
                for function_name in function_names:
                    output_header.write((self._get_function_prototype(function_name) + '\n\n').encode())

        # if self.verbose:
        #     print('[+] Complete! Files written to:')
        #     print(f'\t{basename}.h')
        #     print(f'\t{basename}.c')
        #     if self.arch in [Arch.x64, Arch.Any]:
        #         print(f'\t{basename}{basename_suffix}-asm.x64.asm')
        #     if self.arch in [Arch.x86, Arch.Any]:
        #         print(f'\t{basename}{basename_suffix}-asm.x86.asm')
        #     input("[/] Press a key to continue...")

    def _get_typedefs(self, function_names: list) -> list:
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.typedefs[typedef_id].get('dependencies')
            more_dependencies = list(set(more_dependencies))  # Remove duplicates.

            if more_dependencies:
                # Create new layer.
                i += 1
                typedef_layers[i] = _names_to_ids(more_dependencies)
            else:
                # Remove duplicates between layers.
                for k in range(len(typedef_layers) - 1):
                    typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
                break

        # Get code for each typedef.
        typedef_code = []
        prefix = self.prefix + "_" if self.prefix else ""
        for i in range(max(typedef_layers.keys()), -1, -1):
            for j in typedef_layers[i]:
                code = self.typedefs[j].get('definition')
                if code.startswith('typedef') and code.split(" ")[1] in ["const", "struct", "enum"]:
                    pname = code.split(" ")[2].split("\n")[0].strip()
                    name = pname[1:]
                    if pname in self.already_defined_types:
                        continue

                typedef_code.append(code)

        return typedef_code

    def _fix_type(self, _type: str) -> str:
        return _type
        # if self.prefix in [None, ""]:
        #     return _type
        # if _type in self.structured_types:
        #     return self.prefix + "_" + _type
        #
        # elif _type.startswith("P") and _type[1:] in self.structured_types:
        #     return "P" + self.prefix + "_" + _type[1:]
        #
        # return _type

    def _get_function_prototype(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {self.prefix}{function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]

                _type = self._fix_type(param['type'])

                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{_type} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature
    
    def _get_function_define(self, function_name: str,index) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {self.prefix}{function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]

                _type = self._fix_type(param['type'])

                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{_type} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ')\n{'
            
            signature += '\n\treturn SyscallStub(Syscalls[{}],'.format(index)
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]

                signature += f'{param["name"]}'
                signature += ',' if i < num_params - 1 else ');' 
        else:
            signature += '){'
            signature += '\n\treturn SyscallStub(Syscalls[{}]);\n'.format(index)

        signature += '\n}'
        return signature

    def _get_function_hash(self, function_name: str):
        hash = self.seed
        name = function_name.replace('Nt', 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)

        return hash


if __name__ == '__main__':
    print("SysWhispersR7: Syscall in Rapid7 to SysWhispers\n")
    print("Most Source Code from:  \n")
    print("https://github.com/rapid7/ReflectiveDLLInjection\n")
    print("https://github.com/klezVirus/SysWhispers3\n\n")

    parser = argparse.ArgumentParser(description="SysWhispersR7: Syscall in Rapid7 to SysWhispers")
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-a', '--arch', default="x64", choices=["x86", "x64", "all"], help='Architecture',
                        required=False)
    parser.add_argument('-c', '--compiler', default="msvc", choices=["msvc", "mingw", "all"], help='Compiler',
                        required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    parser.add_argument('-P', '--prefix', default="SWR7", type=str,
                        help='Add prefix to function names to avoid pollution', required=False)

    args = parser.parse_args()


    arch = Arch.from_string(args.arch)
    compiler = Compiler.from_string(args.compiler)

    sw = SysWhispers(
        arch=arch,
        compiler=compiler,
        prefix=args.prefix
    )
    print()

    if args.preset == 'all':
        print('[I] All functions selected.\n')
        sw.generate(basename=args.out_file)

    elif args.preset == 'common':
        print('[I] Common functions selected.\n')
        sw.generate(
            ['NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenProcessToken',
             'NtTestAlert',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'],
            basename=args.out_file)

    elif args.preset:
        print('[-] Invalid preset provided. Must be "all" or "common".')

    elif not args.functions:
        print('[-] --preset XOR --functions switch must be specified.\n')
        print('[H] ./syswhispers.py --preset common --out-file syscalls_common')
        print('[H] ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

    else:
        functions = args.functions.split(',') if args.functions else []
        sw.generate(functions, args.out_file)
