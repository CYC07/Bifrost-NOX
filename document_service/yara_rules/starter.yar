/*
 * Starter YARA rules for AI Firewall document_service.
 *
 * This is a small curated set targeting common document-borne threats. Drop
 * additional .yar files into this directory (e.g. Neo23x0/signature-base) and
 * they will be auto-loaded by malware_model.load_rules() at startup.
 */

rule EICAR_Test_String
{
    meta:
        description = "EICAR antivirus test signature (regression marker)"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Office_VBA_Macro_Project
{
    meta:
        description = "Office document containing a VBA macro project (vbaProject.bin)"
        severity = "high"
    strings:
        $zip_magic = { 50 4B 03 04 }
        $vba1 = "vbaProject.bin"
        $vba2 = "word/vbaProject.bin"
        $vba3 = "xl/vbaProject.bin"
    condition:
        $zip_magic at 0 and any of ($vba*)
}

rule PDF_JavaScript_Launcher
{
    meta:
        description = "PDF with JavaScript or Launch action wired to an auto-run trigger (/OpenAction, /AA)"
        severity = "high"
    strings:
        $pdf = "%PDF"
        // PDF names end at a delimiter; "/JS" must not match /JSONData etc.
        $js1 = /\/JavaScript([^A-Za-z0-9_.#-]|$)/
        $js2 = /\/JS([^A-Za-z0-9_.#-]|$)/
        $oa  = /\/OpenAction([^A-Za-z0-9_.#-]|$)/
        $aa  = /\/AA([^A-Za-z0-9_.#-]|$)/
        $launch = /\/Launch([^A-Za-z0-9_.#-]|$)/
        // Acrobat form-field helpers (AFNumber_Format, AFDate_FormatEx, ...): benign /AA scripts.
        $af_helper = /\(AF[A-Z][A-Za-z]*_[A-Za-z]+\\?\(/
        $acroform = /\/AcroForm([^A-Za-z0-9_.#-]|$)/
        $launch_s = /\/S\s*\/Launch([^A-Za-z0-9_.#-]|$)/
    condition:
        $pdf in (0..1024) and (
            (($js1 or $js2) and $oa) or
            $launch_s or
            ($launch and $oa) or
            ($aa and ($js1 or $js2) and not $af_helper and not $acroform)
        )
}

rule PDF_Embedded_Executable
{
    meta:
        description = "PDF with embedded file stream containing a real PE/ELF/Mach-O executable header"
        severity = "critical"
    strings:
        $pdf = "%PDF"
        $emb = /\/EmbeddedFile([^A-Za-z0-9_.#-]|$)/
        // MZ alone matches random binary data; require the DOS stub / PE signature.
        $pe_stub = /MZ[\x00-\xff]{58}[\x40-\xf8]\x00\x00\x00[\x00-\xff]{0,248}PE\x00\x00/
        $dos_msg = "This program cannot be run in DOS mode"
        // ELF ident: class, data, version=1, OSABI, ABI version, 7 zero pad bytes
        $elf = { 7F 45 4C 46 (01|02) (01|02) 01 ?? ?? 00 00 00 00 00 00 00 }
    condition:
        $pdf in (0..1024) and $emb and ($pe_stub or $dos_msg or $elf)
}

rule Office_Equation_Editor_CVE_2017_11882
{
    meta:
        description = "OLE equation editor object commonly abused for CVE-2017-11882"
        severity = "critical"
    strings:
        $eq1 = "Equation Native"
        $eq2 = "Microsoft Equation 3.0"
    condition:
        any of ($eq*)
}
