/*
   YARA rule template — Blue Team CTF project
   Replace every placeholder before shipping.
*/

rule Family_Variant_Loader
{
    meta:
        author      = "<handle>"
        date        = "2026-05-29"
        description = "Detects <family> <variant> loader: <one-line behaviour>"
        reference   = "<URL to report>"
        tlp         = "WHITE"
        hash_md5    = "<md5 of one observed sample>"
        hash_sha256 = "<sha256 of one observed sample>"
        version     = "1.0"

    strings:
        // Prefer 3+ distinct strings of length >= 6.
        // Avoid short ASCII that hits every PE.
        $s1 = "uniq_marker_string_1" ascii wide
        $s2 = "C:\\Users\\Public\\evil.dll" ascii nocase
        $s3 = { 6D 6F 64 75 6C 65 5F 69 6E 69 74 }    // "module_init"

        // Imphash and PE specifics where applicable:
        // $pe_imphash = "<imphash hex>"

    condition:
        // Adjust for file type (PE / ELF / Mach-O):
        uint16(0) == 0x5A4D                // MZ for PE
        and filesize < 5MB
        and 2 of ($s*)
}
