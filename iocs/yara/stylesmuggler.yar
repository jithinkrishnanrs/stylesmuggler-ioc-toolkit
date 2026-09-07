/*
    StyleSmuggler implant — YARA rules
    Built from published/observed indicators only (strings, paths, C2 hosts).
    Sources: Sansec advisory (2026-09-05) + community IR write-ups on two confirmed
    live infections, same date. See ../../docs/VULNERABILITY.md.

    Usage:
        yara -r stylesmuggler.yar /                      # filesystem sweep
        yara -r stylesmuggler.yar $(pgrep -f kworker)     # if your yara build supports -p / process scanning

    NOTE: these rules key off strings and known hashes gathered from public reporting,
    not off a sample this repo ships or was built by disassembling. Expect false
    negatives against future variants — the attacker has already changed the trigger
    header format once within 24 hours of disclosure. Pair this with the behavioral
    checks in scripts/stylesmuggler_scan.sh, which do not depend on any of these
    literal strings.
*/

import "hash"

rule StyleSmuggler_Implant_Hash
{
    meta:
        description = "Matches known StyleSmuggler (gvfsd-user) implant hashes"
        source = "Sansec advisory 2026-09-05 + community IR"
        reference = "https://sansec.io/research/stylesmuggler"
        date = "2026-09-06"

    condition:
        hash.sha256(0, filesize) == "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7" or
        hash.sha256(0, filesize) == "8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef" or
        hash.sha256(0, filesize) == "251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220"
}

rule StyleSmuggler_Implant_Strings
{
    meta:
        description = "Heuristic match on StyleSmuggler C2/persistence strings embedded in a candidate binary"
        source = "Sansec advisory 2026-09-05 + community IR"
        reference = "https://sansec.io/research/stylesmuggler"
        date = "2026-09-06"

    strings:
        $c2_1        = "99.84.67.186"
        $c2_2        = "247.cdnflare.xyz"
        $c2_3        = "windwsecurity.run"
        $c2_4        = "ntp.timesysnc.net"
        $c2_5        = "time.microsft.run"
        $c2_6        = "pool.microsft.studio"
        $path_1      = ".gvfsd"
        $path_2      = "gvfsd-user"
        $path_3      = ".kw_"
        $masquerade  = "kworker/u:8:0"

    condition:
        // Rust ELF profile: stripped, statically linked, ~1.9MB, x86-64 or arm64
        uint32(0) == 0x464c457f and
        filesize < 4MB and
        2 of ($c2_*, $path_*, $masquerade)
}

rule StyleSmuggler_Poisoned_Log_Marker
{
    meta:
        description = "Matches the MG<hex>::...::/MG<hex> execution-proof marker in logs or response captures"
        source = "Community IR, 2026-09-05"
        date = "2026-09-06"

    strings:
        $marker = /MG[0-9a-f]{16,}::.{0,4096}::\/MG[0-9a-f]{16,}/

    condition:
        $marker
}
