rule BeaverTail_Domain{
    meta:
        description = "Detects BeaverTail C2 domain"
        author = "rikychoi"
        date = "2026-04-15"
    strings:
        $d1 = "146.70.253.107" ascii wide
    condition:
        any of them
}

rule crypto_exfiltration{
    meta:
        description = "Detects exfiltration of crypto data"//BeaverTail and InvisibleFerret
        author = "rikychoi"
        date = "2026-04-15"
    strings:
        $browser1 = "Firefox" ascii wide nocase
        $browser2 = "Chrome" ascii wide nocase
        $browser3 = "Opera" ascii wide nocase
        $browser4 = "Brave" ascii wide nocase
        $c_e1 = "binance" ascii wide nocase
        $c_e2 = "kraken" ascii wide nocase
        $c_e3 = "OKX" ascii wide nocase
        $c_e4 = "bybit" ascii wide nocase
        $c_w1 = "metamask" ascii wide nocase
        $c_w2 = "Exodus" ascii wide nocase
        $c_w3 = "Solana" ascii wide nocase
        $c_w4 = "phantom" ascii wide nocase
        $send1 = "request.post" ascii wide
        $send2 = "requests.post" ascii wide
    condition:
        any of ($send*) and
        5 of ($c*) and
        3 of (&browser)
}

