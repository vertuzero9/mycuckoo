SIMPLE_CATEGORIES = {
    "properties":[
        "has_authenticode", "has_pdb", "pe_features", "packer_upx", "has_wmi"
    ],
    "behaviour":[
        "dumped_buffer2", "suspicious_process", "persistence_autorun",
        "raises_exception", "sniffer_winpcap", "injection_runpe",
        "dumped_buffer", "exec_crash", "creates_service",
        "allocates_rwx"
    ],
    "exploration":[
        "recon_fingerprint", "antidbg_windows", "locates_sniffer"
    ],
    "mutex":[
        "ardamax_mutexes", "rat_xtreme_mutexes", "bladabindi_mutexes"
    ],
    "networking":[
        "network_bind", "networkdyndns_checkip", "network_http",
        "network_icmp", "recon_checkip", "dns_freehosting_domain",
        "dns_tld_pw", "dns_tld_ru"
    ],
    "filesystem":[
        "modifies_files", "packer_polymorphic", "creates_exe",
        "creates_doc"
    ],
    "security":[
        "rat_xtreme", "disables_security", "trojan_redosru",
        "worm_renocide", "antivirus_virustotal"
    ],
    "virtualisation":[
        "antivm_vbox_files", "antivm_generic_bios", "antivm_vmware_keys",
        "antivm_generic_services", "antivm_vmware_files", "antivm_sandboxie",
        "antivm_vbox_keys", "antivm_generic_scsi", "antivm_vmware_in_instruction",
        "antivm_generic_disk", "antivm_virtualpc"
    ],
    "sanbox":[
        "antisandbox_unhook", "antisandbox_mouse_hook", "antisandbox_foregroundwindows",
        "antisandbox_productid", "antisandbox_idletime", "antisandbox_sleep"
    ],
    "infostealer":[
        "infostealer_browser", "infostealer_mail", "infostealer_keylogger",
        "infostealer_ftp",
    ],
    "ransomware":[
        "ransomware_files", "ransomware_bcdedit"
    ]
}

CATEGORIES = {
    "static":{
        ":meta:":[
            "",
            "size",
            "timestamp"
        ],
        ":sign:":[
            "",
            "signed"
        ],
        ":heur:":[
            ""
        ],
        ":pack:":[
            ""
        ],
        ":pef:":[
            "lang:"
        ],
        ":simp:":[
            "",
            "count"
        ]
    },
    "dynamic":{
        ":dimp:":[
            "",
            "proc:",
            "mutex:"
        ],
        ":file:":{
            "touch:":[
                ""
            ],
            "count:":[
                "",
                "all",
                "read",
                "written",
                "deleted",
                "copied",
                "renamed",
                "opened",
                "exists",
                "failed"
            ]
        },
        ":net:":[
            ""
        ],
        ":reg:":[
            "",
            "write:",
            "del:"
        ],
        ":win:":[
            ""
        ]
    },
    "counts":{
        ":count:":{
            "lang":[""],
            "simp":[
                "",
                ":"
            ],
            "proc":[""],
            "dimp":[""],
            "file:":[
                "",
                "all",
                "read",
                "written",
                "deleted",
                "copied",
                "renamed",
                "opened",
                "exists",
                "failed"
            ],
            "tcp":[""],
            "udp":[""],
            "dns":[""],
            "http":[""],
            "reg:":[
                "",
                "write",
                "del"
            ],
            "wapi":[""]
        }
    }
}

PATTERNS = [r"Armadillo", r"PECompact", r"ASPack", r"ASProtect",
    r"Upack", r"U(PX|px)", r"FSG", r"BobSoft Mini Delphi",
    r"InstallShield 2000", r"InstallShield Custom",
    r"Xtreme\-Protector", r"Crypto\-Lock", r"MoleBox", r"Dev\-C\+\+",
    r"StarForce", r"Wise Installer Stub", r"SVK Protector",
    r"eXPressor", r"EXECryptor", r"N(s|S)Pac(k|K)", r"KByS",
    r"themida", r"Packman", r"EXE Shield", r"WinRAR 32-bit SFX",
    r"WinZip 32-bit SFX", r"Install Stub 32-bit", r"P(E|e)tite",
    r"PKLITE32", r"y(o|0)da's (Protector|Crypter)", r"Ste@lth PE",
    r"PE\-Armor", r"KGB SFX", r"tElock", r"PEBundle", r"Crunch\/PE",
    r"Obsidium", r"nPack", r"PEX", r"PE Diminisher",
    r"North Star PE Shrinker", r"PC Guard for Win32", r"W32\.Jeefo",
    r"MEW [0-9]+", r"InstallAnywhere", r"Anskya Binder",
    r"BeRoEXEPacker", r"NeoLite", r"SVK\-Protector",
    r"Ding Boy's PE\-lock Phantasm", r"hying's PEArmor", r"E language",
    r"NSIS Installer", r"Video\-Lan\-Client", r"EncryptPE",
    r"HASP HL Protection", r"PESpin", r"CExe", r"UG2002 Cruncher",
    r"ACProtect", r"Thinstall", r"DBPE", r"XCR", r"PC Shrinker",
    r"AH(p|P)ack", r"ExeShield Protector",
    r"\* \[MSLRH\]", r"XJ \/ XPAL", r"Krypton", r"Stealth PE",
    r"Goats Mutilator", r"PE\-PACK", r"RCryptor", r"\* PseudoSigner",
    r"Shrinker", r"PC-Guard", r"PELOCKnt", r"WinZip \(32\-bit\)",
    r"EZIP", r"PeX", r"PE( |\-)Crypt", r"E(XE|xe)()?Stealth",
    r"ShellModify", r"Macromedia Windows Flash Projector\/Player",
    r"WARNING ->", r"PE Protector", r"Software Compress",
    r"PE( )?Ninja", r"Feokt", r"RLPack",
    r"Nullsoft( PIMP)? Install System", r"SDProtector Pro Edition",
    r"VProtector", r"WWPack32", r"CreateInstall Stub", r"ORiEN",
    r"dePACK", r"ENIGMA Protector", r"MicroJoiner", r"Virogen Crypt",
    r"SecureEXE", r"PCShrink", r"WinZip Self\-Extractor",
    r"PEiD\-Bundle", r"DxPack", r"Freshbind", r"kkrunchy"]
