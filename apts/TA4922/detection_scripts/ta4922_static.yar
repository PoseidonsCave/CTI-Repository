/*
    Local TA4922-correlated / Cruciferra defensive static detections

    Scope notes:
    - The Cruciferra family rule is derived from one TA4922-corroborated chain
      and one technically related local Tax-Number image.
    - The 119863 image is not independently attributed to TA4922.
    - Exact-build rules are hash matches and do not generalize.
    - Local evidence does not establish TA4922 specificity for VenomRAT or
      ardrv.sys components.

    License: Apache-2.0
*/

import "hash"
import "pe"

private rule Cruciferra_TaxNumber_Static_Core
{
    strings:
        $container_count_two = "PRPPPPPP" ascii

        // Little-endian immediates used by the custom 24-round ARX stream transform.
        $arx_phi  = { B9 79 37 9E }
        $arx_sha0 = { 67 E6 09 6A }
        $arx_sha1 = { 85 AE 67 BB }

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        (pe.characteristics & 0x2000) != 0 and
        pe.exports("GetUserNameExW") and
        filesize > 8MB and
        all of ($arx_*) and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".reloc" and
            pe.sections[i].raw_data_size > 6500000 and
            @container_count_two >= pe.sections[i].raw_data_offset and
            @container_count_two <
                pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
        )
}

rule Cruciferra_Local_TaxNumber_Static : malware cruciferra
{
    meta:
        description = "Detects the locally observed Cruciferra Tax-Number cluster using its side-load export, oversized encoded .reloc container, custom ARX constants, build marker, and jkhi overlay tail"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "medium"
        scope = "family-or-close-variant"
        sample_count = 2

    strings:
        $marker_33863  = "SetOdgovorila" ascii
        $marker_119863 = "ShinBijesa" ascii

    condition:
        Cruciferra_TaxNumber_Static_Core and
        1 of ($marker_*) and
        (
            uint32(filesize - 4) == 0x69686b6a or // "jkhi"
            uint32(filesize - 4) == 0x49484b4a    // "JKHI"
        )
}

rule TA4922_Cruciferra_TaxNumber33863_Exact : malware ta4922 cruciferra
{
    meta:
        description = "Exact malicious Secur32.dll from the TA4922 Tax-Number33863 build"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-build"
        sha256 = "ddebc8ccab9f58eb37c48937926ecd51c7973afef9dcf066afd602944a4f5a9f"

    condition:
        filesize == 378564096 and
        hash.sha256(0, filesize) ==
            "ddebc8ccab9f58eb37c48937926ecd51c7973afef9dcf066afd602944a4f5a9f"
}

rule Cruciferra_TaxNumber119863_Exact : malware cruciferra
{
    meta:
        description = "Exact malicious Secur32.dll from the related local Tax-Number119863 image"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-build"
        attribution = "related local Cruciferra artifact; TA4922 attribution not independently established"
        sha256 = "5f7e21981f76e7c1c909d92969858eff990e23ddc21071d7fe8ec1603994121d"

    condition:
        filesize == 331219968 and
        hash.sha256(0, filesize) ==
            "5f7e21981f76e7c1c909d92969858eff990e23ddc21071d7fe8ec1603994121d"
}

rule TA4922_VenomRAT_Payload_Config_Cluster : malware ta4922 venomrat
{
    meta:
        description = "Detects the statically embedded VenomRAT salt and build-specific Base64 configuration key recovered from the decrypted TA4922 payload"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "payload-cluster"
        family_attribution = "VenomRAT-derived; local evidence does not establish TA4922 specificity"

    strings:
        $venom_salt = "VenomRATByVenom" wide
        $config_key_b64 = "UkZra1ZzVmVweVFxM2tIUXRJY21OZHhZQ0JPdWFsTWI=" wide

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        $venom_salt and
        $config_key_b64
}

rule VenomRAT_Managed_Plugin_Protocol_Surface : malware venomrat
{
    meta:
        description = "Detects the managed VenomRAT-derived plugin and MessagePack command surface recovered from the TA4922 payload"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "medium"
        scope = "payload-family-capability"
        attribution = "none; local evidence does not establish TA4922 specificity"

    strings:
        $salt = "VenomRATByVenom" wide

        $type_reverse_proxy = "PluginReverseProxy" ascii
        $type_send_memory = "PluginSendMemory" ascii
        $type_cookie_grabber = "CdpCookieGrabber" ascii

        $packet_key = "Pac_ket" wide
        $reverse_proxy = "REVERSE_PROXY" wide
        $send_memory = "sendMemory" wide
        $fake_binder = "fakeBinder" wide
        $netstat_typo = "CLINENETSTATT_INFO" wide
        $send_memory_typo = "SEND_MOMORY" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        pe.data_directories[14].size > 0 and
        $salt and
        2 of ($type_*) and
        4 of ($packet_key, $reverse_proxy, $send_memory, $fake_binder,
              $netstat_typo, $send_memory_typo)
}

rule VenomRAT_StormKitty_Browser_Recovery_Surface : malware venomrat
{
    meta:
        description = "Detects the StormKitty-referencing Chromium CDP, DPAPI, and Firefox NSS recovery implementation bundled in the recovered VenomRAT payload"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "payload-capability-cluster"
        attribution = "none; embedded reference and capability do not establish actor specificity"

    strings:
        $lineage = "https://github.com/LimerBoy/StormKitty" ascii
        $cdp_type = "CdpCookieGrabber" ascii
        $cdp_command = "Network.getAllCookies" wide
        $cdp_launch = "--remote-debugging-port={0} --headless=new --user-data-dir=\"{1}\" --disable-gpu --disable-logging" wide
        $dpapi = "CryptUnprotectData" ascii
        $firefox_nss = "PK11SDR_Decrypt" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        pe.data_directories[14].size > 0 and
        5 of them
}

rule VenomRAT_Embedded_ToggleDefender_Resource : malware venomrat
{
    meta:
        description = "Detects the embedded ToggleDefender PowerShell resource recovered from the VenomRAT-derived payload"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "payload-capability-cluster"
        attribution = "none; local evidence does not establish TA4922 specificity"

    strings:
        $toggle = "ToggleDefender" ascii
        $cleanup = "SilentCleanup" ascii
        $service = "sc.exe config windefend depend= RpcSs-TOGGLE" ascii
        $health = "SecurityHealthSystray" ascii
        $marker = "#-_-#" ascii
        $mpcmd = "MpCmdRun.exe" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        pe.data_directories[14].size > 0 and
        5 of them
}

rule VenomRAT_hVNC_609_Component : malware venomrat
{
    meta:
        description = "Detects the statically carved VenomRAT 6.0.9 hVNC component by build path and interaction surface"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "payload-component"
        attribution = "none; local evidence does not establish TA4922 specificity"

    strings:
        $pdb = "Venom Project\\BigEye Final(2025-04-06) Released\\HVNCDll\\obj\\Release\\hvnc.pdb" ascii
        $namespace = "Hidden_HVNC_DLL.Functions" ascii
        $browser = "DLL.Browser" ascii
        $receive = "ReceiveCommand" ascii
        $render = "RenderScreenshot" ascii
        $click_left = "PostClickLD" ascii
        $click_right = "PostClickRD" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        pe.data_directories[14].size > 0 and
        $pdb and
        5 of ($namespace, $browser, $receive, $render,
              $click_left, $click_right)
}

rule VenomRAT_hVNC_609_Exact_Component : malware venomrat
{
    meta:
        description = "Exact hVNC component carved from the locally recovered VenomRAT-derived payload resource"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-component"
        attribution = "component correlation only; actor attribution not established"
        sha256 = "e0bef7f04afe55b8d90261f6e64a6f7874dccf9f901080bd0c540e637c80f6dc"

    condition:
        filesize == 38912 and
        hash.sha256(0, filesize) ==
            "e0bef7f04afe55b8d90261f6e64a6f7874dccf9f901080bd0c540e637c80f6dc"
}

rule Cruciferra_Local_Build_Key_Material : malware cruciferra
{
    meta:
        description = "Detects build-specific Cruciferra outer-key material paired with its Tax-Number marker; the 119863 key appears after NativeAOT hydration"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-build-file-or-process-memory"
        attribution = "33863 is TA4922-corroborated; 119863 is a related local artifact"

    strings:
        $key_33863 = "s48HMc+v1q2wm3p6ZtUiYNqAe9XKkFeoCBwm3jQIW+OoqVA6qJjI/GxNtFyWQqlT" wide
        $marker_33863 = "SetOdgovorila" ascii

        $key_119863 = "yew5kW3JeeA0VwtY64gP3vSjpGBSFBg3rd6p/PyiMRrBU1uTx68FQEf/4plE0a2A" wide
        $marker_119863 = "ShinBijesa" ascii

    condition:
        ($key_33863 and $marker_33863) or
        ($key_119863 and $marker_119863)
}

rule TA4922_VenomRAT_Payload_Exact : malware ta4922 venomrat
{
    meta:
        description = "Exact decrypted VenomRAT-derived client payload from the TA4922 Tax-Number33863 build"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-build"
        family_attribution = "VenomRAT-derived; local evidence does not establish TA4922 specificity"
        sha256 = "fbeb3ab69d49c15b18e7c3024c5ed76d0a93442df3e62805d6d352cab73885dd"

    condition:
        filesize == 3386368 and
        hash.sha256(0, filesize) ==
            "fbeb3ab69d49c15b18e7c3024c5ed76d0a93442df3e62805d6d352cab73885dd"
}

rule TA4922_VenomRAT_Decrypted_Config_609 : malware ta4922 venomrat
{
    meta:
        description = "Detects the exact VenomRAT version banner after configuration decryption or in process memory"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "decrypted-config-or-memory"
        family_attribution = "VenomRAT-derived; local evidence does not establish TA4922 specificity"

    strings:
        $version = "RAT + hVNC  6.0.9 Cracked By t.me/VidBckup" ascii wide
        $mutex = "fldnqpgqpzd" ascii wide
        $c2_1 = "103.59.103.93" ascii wide
        $c2_2 = "103.97.128.141" ascii wide

    condition:
        $version and
        $mutex and
        1 of ($c2_*)
}

rule Ardrv_AppRemover_17744_Exact : byovd vulnerable_driver
{
    meta:
        description = "Exact OPSWAT AppRemover ardrv.sys driver decrypted from the local Cruciferra build"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "exact-component"
        attribution = "none"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-36425"
        component_note = "Legitimate but vulnerable driver; hash presence alone does not establish actor attribution"
        sha256 = "07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541"

    condition:
        filesize == 17744 and
        hash.sha256(0, filesize) ==
            "07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541"
}

rule Vulnerable_Ardrv_AppRemover_Component : byovd vulnerable_driver
{
    meta:
        description = "Identifies the vulnerable OPSWAT AppRemover ardrv.sys component by product version and device names"
        author = "PoseidonsCave"
        date = "2026-07-30"
        license = "Apache-2.0"
        confidence = "high"
        scope = "component-family"
        attribution = "none"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-36425"
        component_note = "Legitimate but vulnerable driver that can be abused for BYOVD"

    strings:
        $product = "AppRemover" wide
        $version = "2017.10.02.1551" wide
        $device = "\\Device\\ardrv" wide
        $dos_device = "\\DosDevices\\ardrv" wide

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        all of them
}
