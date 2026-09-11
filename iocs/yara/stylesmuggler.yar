/*
    StyleSmuggler / CVE-2026-75650 — YARA rules
    Built from published/observed indicators only (strings, paths, C2 hosts, campaign
    markers). Covers BOTH the Rust implant campaign (gvfsd-user/fc-cache/chronyd) AND
    the second, unrelated PHP web-shell attacker confirmed 2026-09-07 — these are two
    separate rule groups for two separate operators using the same entry point.
    Sources: Sansec advisory (2026-09-05, updated through at least 2026-09-09) + Adobe
    APSB26-146 + community IR write-ups. See ../../docs/VULNERABILITY.md.

    Usage:
        yara -r stylesmuggler.yar /                      # filesystem sweep
        yara -r stylesmuggler.yar $(pgrep -f kworker)     # if your yara build supports -p / process scanning

    NOTE: these rules key off strings and known hashes gathered from public reporting,
    not off a sample this repo ships or was built by disassembling. Expect false
    negatives against future variants — the attacker has already changed the trigger
    header format once within 24 hours of disclosure, and both implant version and
    the second attacker's campaign markers change per-drop. Pair this with the
    behavioral checks in scripts/stylesmuggler_scan.sh, which do not depend on any of
    these literal strings.
*/

import "hash"

rule StyleSmuggler_Implant_Hash
{
    meta:
        description = "Matches known StyleSmuggler implant hashes across all observed builds (gvfsd-user, fc-cache, chronyd)"
        source = "Sansec advisory 2026-09-05, updated through at least 2026-09-09 + community IR"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        date = "2026-09-09"

    condition:
        // gvfsd-user build
        hash.sha256(0, filesize) == "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7" or
        hash.sha256(0, filesize) == "8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef" or
        hash.sha256(0, filesize) == "251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220" or
        // fc-cache / chronyd build
        hash.sha256(0, filesize) == "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420" or
        hash.sha256(0, filesize) == "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e" or
        hash.sha256(0, filesize) == "d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82" or
        hash.sha256(0, filesize) == "1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d"
}

rule StyleSmuggler_SecondAttacker_Dropper_Hash
{
    meta:
        description = "Matches the second, unrelated attacker's PHP web-shell dropper by hash. SEPARATE campaign from the Rust implant rules above."
        source = "Sansec advisory, updated 2026-09-09"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        date = "2026-09-09"

    condition:
        hash.sha256(0, filesize) == "d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e"
}

rule StyleSmuggler_Implant_Strings
{
    meta:
        description = "Heuristic match on StyleSmuggler C2/persistence strings embedded in a candidate binary, across all observed builds"
        source = "Sansec advisory 2026-09-05, updated through 2026-09-07 + community IR"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        date = "2026-09-07"

    strings:
        // gvfsd-user build C2/paths
        $c2_1        = "99.84.67.186"
        $c2_2        = "247.cdnflare.xyz"
        $c2_3        = "windwsecurity.run"
        $c2_4        = "ntp.timesysnc.net"
        $c2_5        = "time.microsft.run"
        $c2_6        = "pool.microsft.studio"
        $path_1      = ".gvfsd"
        $path_2      = "gvfsd-user"
        $path_3      = ".kw_"
        $masquerade_1 = "kworker/u:8:0"

        // fc-cache / chronyd build C2/paths
        $c2_7        = "ntp.timesync.to"
        $c2_8        = "ntp.synctime.to"
        $c2_9        = "ntp.syncstime.to"
        $path_4      = "fontconfig/fc-cache"
        $path_5      = ".fc_"
        $path_6      = ".chrony-"
        $masquerade_2 = "chronyd"

    condition:
        // Rust ELF profile: stripped, statically linked, ~1.9MB, x86-64 or arm64
        uint32(0) == 0x464c457f and
        filesize < 4MB and
        2 of ($c2_*, $path_*, $masquerade_*)
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

rule StyleSmuggler_SecondAttacker_WebShell
{
    meta:
        description = "Matches the second, unrelated attacker's PHP web shell/recon-probe artefacts (confirmed 2026-09-07, expanded 2026-09-09) - filename pattern, campaign markers, auth-gate header, and OOB exfil domain suffix. This is a SEPARATE campaign from the Rust implant rules above."
        source = "Sansec advisory, updated through at least 2026-09-09"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        date = "2026-09-09"

    strings:
        $path          = "catalog/product/cache/ss_"
        $marker_drop    = /ss5_[0-9a-f]{10}/
        $marker_recon   = /ss6_[0-9a-f]{10}/
        $marker_drop_exact  = "ss5_457cfa2fb7"
        $marker_recon_exact = "ss6_457cfa2fb7_"
        $exfil_tld     = ".oast.site"
        $wpm_flag      = "w_pm"
        $auth_header   = "X-Cache-Token: fced27f6d57702565353ecc11722533b"

    condition:
        any of them
}
