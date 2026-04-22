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
        description = "PDF containing /JavaScript or /OpenAction auto-launch keys"
        severity = "high"
    strings:
        $pdf = "%PDF"
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $oa  = "/OpenAction"
        $aa  = "/AA"
        $launch = "/Launch"
    condition:
        $pdf at 0 and (
            ($js1 and $oa) or
            ($js2 and $oa) or
            $launch or
            ($aa and ($js1 or $js2))
        )
}

rule PDF_Embedded_Executable
{
    meta:
        description = "PDF with embedded file stream containing Windows/Linux executable header"
        severity = "critical"
    strings:
        $pdf = "%PDF"
        $emb = "/EmbeddedFile"
        $mz  = "MZ"
        $elf = { 7F 45 4C 46 }
    condition:
        $pdf at 0 and $emb and ($mz or $elf)
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
