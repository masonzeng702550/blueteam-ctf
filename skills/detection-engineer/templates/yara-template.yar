rule Family_Variant_Loader
{
    meta:
        author      = "<handle>"
        date        = "2026-05-29"
        description = "Detects <family> <variant>"
        reference   = "<URL>"
        tlp         = "WHITE"
        hash_sha256 = "<sha256>"

    strings:
        $s1 = "uniq_marker_string_1" ascii wide
        $s2 = "C:\\Users\\Public\\evil.dll" ascii nocase
        $s3 = { 6D 6F 64 75 6C 65 5F 69 6E 69 74 }

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($s*)
}
