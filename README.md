

## Usage
```bash
-p: required.
Usage: VMP-Imports-Deobfuscator [options]

Optional arguments:
-h --help       shows help message and exits
-v --version    prints version information and exits
-p --pid        Target process pid [required]
-m --module     Target module name [default: ""]
-i --iat        section that is used to storage new IAT in memory, it maybe destroy vmp code [default: ".rdata"]
-d --dump       fix iat & dump to file [default: false]
-o --oep        if need dump,you can input oep with prefix,eg:0x1234 [default: "0x0"]
```

Example usage:
```bash
VMP-Imports-Deobfuscator.exe -p 1234
VMP-Imports-Deobfuscator.exe -p 1234 -m "sample.dll"
VMP-Imports-Deobfuscator.exe -p 1234 -m "sample.dll" -i ".sec0"
VMP-Imports-Deobfuscator.exe -p 1234 -d -o 0x1234
```



## Credits

- github.com/lo1see/VMP-IAT-recover
- github.com/KuNgia09/vmp3-import-fix
- github.com/PlaneJun/VMP-Import-Fix



- github.com/woxihuannisja
- github.com/unicorn-engine/unicorn
- github.com/DarthTon/Blackbone
- github.com/archercreat/vmpfix
- github.com/zyantific/zydis


## Update
- Support 32-bit programs
- Add dump feature and modify OEP feature

