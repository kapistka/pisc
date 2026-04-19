# Public OCI-Image Security Checker

## What is it?

PISC (Public OCI-Image or docker-image Security Checker) is command-line tool to assess the security of OCI container images.  
Exits with code `1` if any of the following conditions are met:
* **malware** 🍄 (exploits 🐙, hack-tools 👾, backdoors 🐴, crypto-miners 💰, etc 💩) by [virustotal](https://www.virustotal.com/) and YARA
* exploitable critical **vulnerabilities** 🐞 by [trivy](https://github.com/aquasecurity/trivy), [grype](https://github.com/anchore/grype), [epss](https://epss.empiricalsecurity.com) and [inthewild.io](https://inthewild.io/)
* image **misconfigurations** 🐳 like [CVE-2024-21626](https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/)
* old **creation date** 📆
* [non-version](https://docs.docker.com/engine/security/trust/#image-tags-and-dct) **tag** ⚓ (latest, etc)
  
It can be used to automatically check the security of public OCI images before running them in a private environment or using them as base images in a CI/CD pipeline.
<p align="center">
  <img src="./sample-v0.19.0.png" alt="sample">
</p>

## Releases here:
* https://hub.docker.com/r/kapistka/pisc/tags
* [changelog](./changelog.txt)

## Usage

### Preparation
[Get API key](https://docs.virustotal.com/docs/please-give-me-an-api-key) for [virustotal](https://www.virustotal.com/). The standard free end-user account has limitations.

### Quick Start via Docker
```sh
docker run kapistka/pisc:latest /bin/bash ./scan.sh -delmy --virustotal-key <virustotal-api-key> -i r0binak/mtkpi:v1.7.6
```

### Quick Start via Docker-image with offline feeds
```sh
docker run --read-only --tmpfs=/tmp kapistka/pisc:latest-feeds /bin/bash ./scan.sh -delmy --offline-feeds --virustotal-key <virustotal-api-key> -i r0binak/mtkpi:v1.7.6
```

### Common Start
Refer to the [Dockerfile](./Dockerfile#L5) for a list of dependencies. You need to install `trivy`, `grype`, `skopeo`, `yara`, `jq` and other packages based on the distribution you are using.
```bash
Usage:
  scan.sh [flags] [-i IMAGE | -f FILE | --tar TARFILE]

Flags:
  --auth-file <string>            Path to the auth file (see 'scan-download-unpack.sh#L14')
  -d, --date                      Check image age against threshold (default: 365 days).
  --d-days <int>                  Custom threshold for build date check (in days). Example: '--d-days 180'.
  -e, --exploits                  Check for vulnerabilities with known exploits (using Trivy + Grype + inthewild.io + empiricalsecurity.com).
  --epss-and                      Use AND logic to combine EPSS score and exploit presence. If disabled, OR logic is applied (default: OR).
  --epss-min <float>              Minimum EPSS score threshold used for filtering vulnerabilities (default: 0.5).
  --exclusions-file <string>      Path to the exclusions file (see 'check-exclusion.sh#L5')
  -f, --file <string>             Batch scan images from file. Example: '-f /path/to/images.txt'.
  -h, --help                      Display this help message.
  --ignore-errors                 Ignore errors from external tools and continue execution.
  -i, --image <string>            Single image to scan. Example: '-i r0binak/mtkpi:v1.4'.
  -l, --latest                    Detect non-versioned tags (e.g., ':latest').
  -m, --misconfig                 Scan for dangerous build misconfigurations.
  --offline-feeds                 Use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds).
  --output-dir <string>           Output tmp and results file directory. Default /tmp. Example: '--output-dir /tmp'
  --scanner [trivy|grype|all]     Choose which scanner to use: Trivy, Grype, or both (default: all)
  --severity-min <string>         Minimal severity of vulnerabilities [UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL] default [HIGH]
  --show-exploits                 Show exploit details
  --tar <string>                  Scan local TAR archive of image layers. Example: '--tar /path/to/private-image.tar'.
  --trivy-server <string>         Trivy server endpoint URL. Example: '--trivy-server http://trivy.something.io:8080'.
  --trivy-token <string>          Authentication token for Trivy server. Example: '--trivy-token 0123456789abZ'.
  -v, --version                   Display version.
  --virustotal-key <string>       VirusTotal API key for malware scanning. Example: '--virustotal-key 0123456789abcdef'.
  --vulners-key <string>          Vulners.com API key (alternative to inthewild.io). Example: '--vulners-key 0123456789ABCDXYZ'.
  -y, --yara                      Scanning with YARA rules for malware
  --yara-file <string>            Path to additional YARA rules. Example: '--yara-file /path/to/custom-rules.yar'
```

## Usage in CI Pipelines
This utility can be integrated into a CI pipeline to perform a security scan on container images before pushing them to a private registry. Combine this step with image signing and automated registry pushing for a secure DevSecOps workflow. Below is an example configuration:
```yaml
security_scan:
  stage: security
  image: $SECURITY_IMAGE_FEEDS
  script:
    - |
      /bin/bash /home/nonroot/scan.sh -delmy --offline-feeds --virustotal-key $VIRUSTOTAL_API_KEY -f ${NEW_IMAGES_FILE}

      # Auto-approve: If the scan fails (exit code >0), the pipeline stops before reaching this point.
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
```

## Use cases
```bash
# CVE-2024-3094 (XZ Utils) exploit
./scan.sh -y --virustotal-key <virustotal-api-key> -i r0binak/xzk8s:v1.1
════════════════════════════════════════
🍄 r0binak/xzk8s:v1.1 >>> yara detected malicious file
  layer:0f28dfeb
     /lib/x86_64-linux-gnu/liblzma.so.5
       🐴 Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094.
       🐴 liblzma backdoor, encoded strings
       🐴 liblzma backdoored
     /lib/x86_64-linux-gnu/liblzma.so.5.6.0
       🐴 Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094.
       🐴 liblzma backdoor, encoded strings
       🐴 liblzma backdoored
     /usr/lib/x86_64-linux-gnu/liblzma.so.5
       🐴 Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094.
       🐴 liblzma backdoor, encoded strings
       🐴 liblzma backdoored
     /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.0
       🐴 Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094.
       🐴 liblzma backdoor, encoded strings
       🐴 liblzma backdoored
  layer:230cc513
     /root/liblzma.so.5.6.0.patch
       🐴 Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094.
       🐴 liblzma backdoor, encoded strings
       🐴 liblzma backdoored
🍄 r0binak/xzk8s:v1.1 >>> virustotal detected malicious file
   layer:0f28dfeb
     https://www.virustotal.com/gui/file/0f28dfebbf3451ccfe3d5b11d17bc38cc8d1c4e721b842969466dc7989d835e3
     https://www.virustotal.com/gui/file/b17fbd1ffedcd284b8e3f2c2aa0030153493eb7b89d38a5049520fa7f78ab3cc
   layer:230cc513
     https://www.virustotal.com/gui/file/230cc513debf36c5294ba6dd2babd27934bb231362cd8d916ea1c58e9495d38f
     https://www.virustotal.com/gui/file/a45a1816da56f066df0f02a94bfb9a76af349847367a9ce40021283a6273117d
       root/liblzma.so.5.6.0.patch  40/65  🐴  trojan.xzbackdoor/cve20243094
```

```bash
# vulnerabilities: trivy + grype + epss + exploits (IngressNightmare)
./scan.sh -e -i --offline-feeds registry.k8s.io/ingress-nginx/controller:v1.11.2
════════════════════════════════════════════════
🐞 registry.k8s.io/ingress-nginx/controller:v1.11.2 >>> detected exploitable vulnerabilities
   CVE            SEVERITY  SCORE  EPSS  EXPL  FIX  PACKAGE
   CVE-2025-1974  CRITICAL  9.8    0.87  0     +    k8s.io/ingress-nginx
📆 registry.k8s.io/ingress-nginx/controller:v1.11.2 >>> created: 2024-08-15. Last update: 2025-06-04
💡 registry.k8s.io/ingress-nginx/controller:v1.11.2 >>> use a newer tags:
   v1.11.3  v1.11.4         v1.11.5  v1.11.6  v1.11.7
   v1.12.0  v1.12.0-beta.0  v1.12.1  v1.12.2  v1.12.3
```

```bash
# dangerous image build misconfiguration cve-2024-21626
./scan.sh -m -i r0binak/cve-2024-21626:v4
════════════════════════════════════════
🐳 r0binak/cve-2024-21626:v4 >>> detected dangerous misconfiguration
   CVE-2024-21626 runC Escape
     https://nitroc.org/en/posts/cve-2024-21626-illustrated/
```

```bash
# test malware image - https://github.com/ruzickap/malware-cryptominer-container
./scan.sh --virustotal-key <virustotal-api-key> -i peru/malware-cryptominer-container
════════════════════════════════════════
🍄 peru/malware-cryptominer-container >>> yara detected malicious file
  layer:daf0f4a3
     /usr/share/nginx/html/eicar/eicar.com
       💩 Rule to detect the EICAR pattern
     /usr/share/nginx/html/eicar/eicar.com.txt
       💩 Rule to detect the EICAR pattern
     /usr/share/nginx/html/malware/TrojanSpy.MacOS.XCSSET.A.bin
       👾 Yara for the public tool \'roothelper\'. Used by XCSSET (https://gist.github.com/NullArray/f39b026b9e0d19f1e17390a244d679ec)
     /usr/share/nginx/html/malware/Txt.Malware.Sustes.sh
       🐞 Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group
     /usr/share/nginx/html/malware/Unix.Downloader.Rocke.sh
       🐞 Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group
     /usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.sparc
       💩 Detects ELF malware Mirai related
       💩 Detects Mirai Botnet Malware
       💩 Detects new ARM Mirai variant
       💩 Detects suspicious single byte XORed keyword \'Mozilla/5.0\' - it uses yara\'s XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key.
     /usr/share/nginx/html/malware/Unix.Trojan.Spike.elf.arm
       💩 Detects malware from disclosed CN malware set
     /usr/share/nginx/html/malware/WannaCry.exe
       💩 Detects WannaCry Ransomware
       💩 Yara rule that detects WannaCry ransomware.
     /usr/share/nginx/html/xmrig/my-xmrig
       💩 Detects XMRig ELF
       💰 Detects Monero mining software
     /usr/share/nginx/html/xmrig/xmrig
       💩 Detects XMRig ELF
       💰 Detects Monero mining software
🍄 peru/malware-cryptominer-container >>> virustotal detected malicious file
   layer:daf0f4a3
     https://www.virustotal.com/gui/file/daf0f4a3b02d10235152359214a32540b616cf48304628e4b5493d6111d84df6
     https://www.virustotal.com/gui/file/e0b27c2390dc73a1b6a5692cb10018b6ca41d0e9f1e50da2df4f4dad1d484137
       usr/share/nginx/html/eicar/eicar.com.txt                       65/67  🧬  virus.eicar/test
       usr/share/nginx/html/eicar/eicar_com.zip                       60/68  🧬  virus.eicar/test
       usr/share/nginx/html/malware/ILOVEYOU.vbs                      51/62  🐛  worm.loveletter/scriptworm
       usr/share/nginx/html/malware/Invoke-ConPtyShell.ps1            22/51  👾  hacktool.powershell/boxter
       usr/share/nginx/html/malware/L0Lz.bat                          43/62  🐴  trojan.disabler/joke
       usr/share/nginx/html/malware/Linux.Trojan.Multiverze.elf.x86   41/65  🐴  trojan.gafgyt/mirai
       usr/share/nginx/html/malware/MadMan.exe                        36/63  🧬  virus.madman
       usr/share/nginx/html/malware/Melissa.doc                       54/62  🧬  virus.melissa/w97m
       usr/share/nginx/html/malware/Py.Trojan.NecroBot.py             33/62  🐴  trojan.python/necrobot
       usr/share/nginx/html/malware/Trojan.Java.Fractureiser.MTB.jar  25/58  🐴  trojan.java/fractureiser
       usr/share/nginx/html/malware/TrojanSpy.MacOS.XCSSET.A.bin      43/63  🐴  trojan.xcsset/xtesc
       usr/share/nginx/html/malware/Txt.Malware.Sustes.sh             35/59  🐴  trojan.zojfor/shell
       usr/share/nginx/html/malware/Unix.Downloader.Rocke.sh          39/62  🐴  trojan.zojfor/bash
       usr/share/nginx/html/malware/Unix.Malware.Kaiji.elf.arm        37/64  🐴  trojan.kaiji/ddos
       usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.m68k        42/64  🐴  trojan.mirai/bootnet
       usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.mips        46/64  🐴  trojan.gafgyt/mirai
       usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.ppc         47/65  🐴  trojan.gafgyt/mirai
       usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.sparc       43/64  🐴  trojan.mirai/gafgyt
       usr/share/nginx/html/malware/Unix.Trojan.Mirai.elf.x86_64      40/65  🐴  trojan.mirai/gafgyt
       usr/share/nginx/html/malware/Unix.Trojan.Spike.elf.arm         43/64  🐴  trojan.dofloo/rootkit
       usr/share/nginx/html/malware/Walker.com                        41/61  🧬  virus.walker/abraxas
       usr/share/nginx/html/malware/WannaCry.exe                      64/69  🔑  ransomware.wannacry/wannacryptor
       usr/share/nginx/html/malware/Win.Trojan.Perl.perl              37/62  🐴  trojan.perl/shellbot
       usr/share/nginx/html/malware/Zloader.xlsm                      43/66  🐴  trojan.esls/zloader
       usr/share/nginx/html/xmrig/my-xmrig                            13/33  💰  miner.
       usr/share/nginx/html/xmrig/xmrig                               43/65  💰  miner.xmrig/lkoez
```
