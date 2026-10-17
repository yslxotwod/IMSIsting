#!/usr/bin/env python3
"""Check the S6a/S6d (and base Diameter) codec in modules/11_lte_core.sh.

The module states the Diameter header (RFC 6733 §3), the AVP layout (§4),
the S6a/S6d application identifier and command codes (TS 29.272 §7.1,
§7.2), the AVP registry (Table 7.3.1/1 of TS 29.272 plus §4.1 of
RFC 6733), the 3GPP registries of TS 29.230 (Table 4.1 and §5.1) and the
result codes (RFC 6733 §7.1 and TS 29.272 §7.4) in its own tables and
case arms. This script states the same clauses independently, builds
messages from that statement, and compares the module's output field by
field. Wireshark's Diameter dictionaries and dissector are the second
implementation.

Exit status: 0 all agree, 1 a mismatch, 2 no interpreter/module.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

MODULE = os.environ.get("LCORE_MODULE", "modules/11_lte_core.sh")
TSHARK = os.environ.get("TSHARK", "tshark")
WIRESHARK_DIR = os.environ.get("WIRESHARK_DIAMETER_DIR", "/usr/share/wireshark/diameter")

VERBOSE = False
CASES = 0
MISMATCHES = 0
FAILURES = []
NOTES = []


def fail(case, want, got, why=""):
    global MISMATCHES
    MISMATCHES += 1
    FAILURES.append((case, want, got, why))


def check(case, want, got, why=""):
    global CASES
    CASES += 1
    if str(want) != str(got):
        fail(case, want, got, why)
    elif VERBOSE:
        print("ok\t%s" % case)


def note(text):
    NOTES.append(text)
    print("tshark\tNOTE\t%s" % text)


# ── The clauses, as data ────────────────────────────────────────────────
# RFC 6733 §4.1 base AVPs, TS 29.272 Table 7.3.1/1, and RAT-Type (AVP 1032,
# TS 29.212 §5.3.x, reused by §7.3.13 of TS 29.272).
BASE_AVPS = {
    1: 'User-Name', 25: 'Class', 27: 'Session-Timeout',
    33: 'Proxy-State', 44: 'Acct-Session-Id', 50: 'Acct-Multi-Session-Id',
    55: 'Event-Timestamp', 85: 'Acct-Interim-Interval', 257: 'Host-IP-Address',
    258: 'Auth-Application-Id', 259: 'Acct-Application-Id', 260: 'Vendor-Specific-Application-Id',
    261: 'Redirect-Host-Usage', 262: 'Redirect-Max-Cache-Time', 263: 'Session-Id',
    264: 'Origin-Host', 265: 'Supported-Vendor-Id', 266: 'Vendor-Id',
    267: 'Firmware-Revision', 268: 'Result-Code', 269: 'Product-Name',
    270: 'Session-Binding', 271: 'Session-Server-Failover', 272: 'Multi-Round-Time-Out',
    273: 'Disconnect-Cause', 274: 'Auth-Request-Type', 276: 'Auth-Grace-Period',
    277: 'Auth-Session-State', 278: 'Origin-State-Id', 279: 'Failed-AVP',
    280: 'Proxy-Host', 281: 'Error-Message', 282: 'Route-Record',
    283: 'Destination-Realm', 284: 'Proxy-Info', 285: 'Re-Auth-Request-Type',
    287: 'Accounting-Sub-Session-Id', 291: 'Authorization-Lifetime', 292: 'Redirect-Host',
    293: 'Destination-Host', 294: 'Error-Reporting-Host', 295: 'Termination-Cause',
    296: 'Origin-Realm', 297: 'Experimental-Result', 298: 'Experimental-Result-Code',
    299: 'Inband-Security-Id', 480: 'Accounting-Record-Type', 483: 'Accounting-Realtime-Required',
    485: 'Accounting-Record-Number', 1032: 'RAT-Type',
}
TGPP_AVPS = {
    1400: 'Subscription-Data', 1401: 'Terminal-Information', 1402: 'IMEI',
    1403: 'Software-Version', 1404: 'QoS-Subscribed', 1405: 'ULR-Flags',
    1406: 'ULA-Flags', 1407: 'Visited-PLMN-Id', 1408: 'Requested-EUTRAN-Authentication-Info',
    1409: 'Requested-UTRAN-GERAN-Authentication-Info', 1410: 'Number-Of-Requested-Vectors', 1411: 'Re-Synchronization-Info',
    1412: 'Immediate-Response-Preferred', 1413: 'Authentication-Info', 1414: 'E-UTRAN-Vector',
    1415: 'UTRAN-Vector', 1416: 'GERAN-Vector', 1417: 'Network-Access-Mode',
    1418: 'HPLMN-ODB', 1419: 'Item-Number', 1420: 'Cancellation-Type',
    1421: 'DSR-Flags', 1422: 'DSA-Flags', 1423: 'Context-Identifier',
    1424: 'Subscriber-Status', 1425: 'Operator-Determined-Barring', 1426: 'Access-Restriction-Data',
    1427: 'APN-OI-Replacement', 1428: 'All-APN-Configurations-Included-Indicator', 1429: 'APN-Configuration-Profile',
    1430: 'APN-Configuration', 1431: 'EPS-Subscribed-QoS-Profile', 1432: 'VPLMN-Dynamic-Address-Allowed',
    1433: 'STN-SR', 1434: 'Alert-Reason', 1435: 'AMBR',
    1436: 'CSG-Subscription-Data', 1437: 'CSG-Id', 1438: 'PDN-GW-Allocation-Type',
    1439: 'Expiration-Date', 1440: 'RAT-Frequency-Selection-Priority-ID', 1441: 'IDA-Flags',
    1442: 'PUA-Flags', 1443: 'NOR-Flags', 1444: 'User-Id',
    1445: 'Equipment-Status', 1446: 'Regional-Subscription-Zone-Code', 1447: 'RAND',
    1448: 'XRES', 1449: 'AUTN', 1450: 'KASME',
    1452: 'Trace-Collection-Entity', 1453: 'Kc', 1454: 'SRES',
    1456: 'PDN-Type', 1457: 'Roaming-Restricted-Due-To-Unsupported-Feature', 1458: 'Trace-Data',
    1459: 'Trace-Reference', 1462: 'Trace-Depth', 1463: 'Trace-NE-Type-List',
    1464: 'Trace-Interface-List', 1465: 'Trace-Event-List', 1466: 'OMC-Id',
    1467: 'GPRS-Subscription-Data', 1468: 'Complete-Data-List-Included-Indicator', 1469: 'PDP-Context',
    1470: 'PDP-Type', 1471: '3GPP2-MEID', 1472: 'Specific-APN-Info',
    1473: 'LCS-Info', 1474: 'GMLC-Number', 1475: 'LCS-PrivacyException',
    1476: 'SS-Code', 1477: 'SS-Status', 1478: 'Notification-To-UE-User',
    1479: 'External-Client', 1480: 'Client-Identity', 1481: 'GMLC-Restriction',
    1482: 'PLMN-Client', 1483: 'Service-Type', 1484: 'ServiceTypeIdentity',
    1485: 'MO-LR', 1486: 'Teleservice-List', 1487: 'TS-Code',
    1488: 'Call-Barring-Info', 1489: 'SGSN-Number', 1490: 'IDR-Flags',
    1491: 'ICS-Indicator', 1492: 'IMS-Voice-Over-PS-Sessions-Supported', 1493: 'Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions',
    1494: 'Last-UE-Activity-Time', 1495: 'EPS-User-State', 1496: 'EPS-Location-Information',
    1497: 'MME-User-State', 1498: 'SGSN-User-State', 1499: 'User-State',
    1600: 'MME-LocationInformation', 1601: 'SGSN-Location-Information', 1602: 'E-UTRAN-Cell-Global-Identity',
    1603: 'Tracking-Area-Identity', 1604: 'Cell-Global-Identity', 1605: 'Routing-Area-Identity',
    1606: 'Location-Area-Identity', 1607: 'Service-Area-Identity', 1608: 'Geographical-Information',
    1609: 'Geodetic-Information', 1610: 'Current-Location-Retrieved', 1611: 'Age-Of-Location-Information',
    1612: 'Active-APN', 1613: 'SIPTO-Permission', 1614: 'Error-Diagnostic',
    1615: 'UE-SRVCC-Capability', 1616: 'MPS-Priority', 1617: 'VPLMN-LIPA-Allowed',
    1618: 'LIPA-Permission', 1619: 'Subscribed-Periodic-RAU-TAU-Timer', 1621: 'Ext-PDP-Address',
    1622: 'MDT-Configuration', 1623: 'Job-Type', 1624: 'Area-Scope',
    1625: 'List-Of-Measurements', 1626: 'Reporting-Trigger', 1627: 'Report-Interval',
    1628: 'Report-Amount', 1629: 'Event-Threshold-RSRP', 1630: 'Event-Threshold-RSRQ',
    1631: 'Logging-Interval', 1632: 'Logging-Duration', 1633: 'Relay-Node-Indicator',
    1634: 'MDT-User-Consent', 1635: 'PUR-Flags', 1636: 'Subscribed-VSRVCC',
    1637: 'Equivalent-PLMN-List', 1638: 'CLR-Flags', 1639: 'UVR-Flags',
    1640: 'UVA-Flags', 1641: 'VPLMN-CSG-Subscription-Data', 1642: 'Time-Zone',
    1643: 'A-MSISDN', 1645: 'MME-Number-for-MT-SMS', 1648: 'SMS-Register-Request',
    1649: 'Local-Time-Zone', 1650: 'Daylight-Saving-Time', 1654: 'Subscription-Data-Flags',
    1655: 'Measurement-Period-LTE', 1656: 'Measurement-Period-UMTS', 1657: 'Collection-Period-RRM-LTE',
    1658: 'Collection-Period-RRM-UMTS', 1659: 'Positioning-Method', 1660: 'Measurement-Quantity',
    1661: 'Event-Threshold-Event-1F', 1662: 'Event-Threshold-Event-1I', 1663: 'Restoration-Priority',
    1664: 'SGs-MME-Identity', 1665: 'SIPTO-Local-Network-Permission', 1666: 'Coupled-Node-Diameter-ID',
    1667: 'WLAN-offloadability', 1668: 'WLAN-offloadability-EUTRAN', 1669: 'WLAN-offloadability-UTRAN',
    1670: 'Reset-ID', 1671: 'MDT-Allowed-PLMN-Id', 1672: 'Adjacent-PLMNs',
    1673: 'Adjacent-Access-Restriction-Data', 1674: 'DL-Buffering-Suggested-Packet-Count', 1675: 'IMSI-Group-Id',
    1676: 'Group-Service-Id', 1677: 'Group-PLMN-Id', 1678: 'Local-Group-Id',
    1679: 'AIR-Flags', 1680: 'UE-Usage-Type', 1681: 'Non-IP-PDN-Type-Indicator',
    1682: 'Non-IP-Data-Delivery-Mechanism', 1683: 'Additional-Context-ID', 1684: 'SCEF-Realm',
    1685: 'Subscription-Data-Deletion', 1686: 'Preferred-Data-Mode', 1687: 'Emergency-Info',
    1688: 'V2X-Subscription-Data', 1689: 'V2X-Permission', 1690: 'PDN-Connection-Continuity',
    1691: 'eDRX-Cycle-Length', 1692: 'eDRX-Cycle-Length-Value', 1693: 'UE-PC5-AMBR',
    1694: 'MBSFN-Area', 1695: 'MBSFN-Area-ID', 1696: 'Carrier-Frequency',
    1697: 'RDS-Indicator', 1698: 'Service-Gap-Time', 1699: 'Aerial-UE-Subscription-Information',
    1700: 'Broadcast-Location-Assistance-Data-Types', 1701: 'Paging-Time-Window', 1702: 'Operation-Mode',
    1703: 'Paging-Time-Window-Length', 1704: 'Core-Network-Restrictions', 1705: 'eDRX-Related-RAT',
    1706: 'Interworking-5GS-Indicator',
}
APPS = {
    0: 'Diameter Common Messages', 1: 'NASREQ', 2: 'Mobile IPv4',
    3: 'Diameter Base Accounting', 4: 'Credit-Control', 5: 'EAP',
    16777216: '3GPP Cx/Px', 16777217: '3GPP Sh/Ph', 16777218: '3GPP Re',
    16777219: '3GPP Wx', 16777220: '3GPP Zn', 16777221: '3GPP Zh',
    16777222: '3GPP Gq', 16777223: '3GPP Gmb', 16777224: '3GPP Gx',
    16777225: '3GPP Gx over Gy', 16777226: '3GPP MM10', 16777229: '3GPP Rx',
    16777230: '3GPP Pr', 16777236: '3GPP Rx (29.214)', 16777238: '3GPP Gx (29.212)',
    16777250: '3GPP STa', 16777251: '3GPP S6a/S6d', 16777252: "3GPP S13/S13'",
    16777255: '3GPP SLg', 16777264: '3GPP SWm', 16777265: '3GPP SWx',
    16777266: '3GPP Gxx', 16777267: '3GPP S9', 16777268: '3GPP Zpn',
    16777272: '3GPP S6b', 16777291: '3GPP SLh', 16777292: '3GPP SGmb',
    16777302: '3GPP Sy', 16777303: '3GPP Sd', 16777308: '3GPP S7a',
    16777309: '3GPP Tsp', 16777310: '3GPP S6m', 16777311: '3GPP T4',
    16777312: '3GPP S6c', 16777313: '3GPP SGd', 16777318: '3GPP S15',
    16777319: '3GPP S9a', 16777320: '3GPP S9a*', 16777335: '3GPP MB2-C',
    16777336: '3GPP PC4a', 16777337: '3GPP PC2', 16777340: '3GPP PC6/PC7',
    16777342: '3GPP Np', 16777345: '3GPP S6t', 16777346: '3GPP T6a/T6b',
    16777347: '3GPP Ns', 16777348: '3GPP Nt', 16777349: '3GPP St',
    16777350: '3GPP PC2', 16777351: '3GPP Diameter Data',
}
COMMANDS = {
    257: 'Capabilities-Exchange (CER/CEA)', 258: 'Re-Auth (RAR/RAA)', 268: 'Diameter-EAP (DER/DEA)',
    271: 'Accounting (ACR/ACA)', 272: 'Credit-Control (CCR/CCA)', 274: 'Abort-Session (ASR/ASA)',
    275: 'Session-Termination (STR/STA)', 280: 'Device-Watchdog (DWR/DWA)', 282: 'Disconnect-Peer (DPR/DPA)',
    300: 'User-Authorization (UAR/UAA)  [Cx]', 301: 'Server-Assignment (SAR/SAA)  [Cx]', 302: 'Location-Info (LIR/LIA)  [Cx]',
    303: 'Multimedia-Auth (MAR/MAA)  [Cx]', 304: 'Registration-Termination (RTR/RTA)  [Cx]', 305: 'Push-Profile (PPR/PPA)  [Cx]',
    306: 'User-Data (UDR/UDA)  [Sh]', 307: 'Profile-Update (PUR/PUA)  [Sh]', 308: 'Subscribe-Notifications (SNR/SNA)  [Sh]',
    309: 'Push-Notification (PNR/PNA)  [Sh]', 310: 'Bootstrapping-Info (BIR/BIA)  [Zn]', 311: 'Message-Process (MPR/MPA)  [MM10]',
    312: 'GBAPush-Info (GPR/GPI)  [Zn]', 313: 'allocated to 3GPP, not used yet', 316: 'Update-Location (ULR/ULA)  [S6a/S6d]',
    317: 'Cancel-Location (CLR/CLA)  [S6a/S6d]', 318: 'Authentication-Information (AIR/AIA)  [S6a/S6d]', 319: 'Insert-Subscriber-Data (IDR/IDA)  [S6a/S6d]',
    320: 'Delete-Subscriber-Data (DSR/DSA)  [S6a/S6d]', 321: 'Purge-UE (PUR/PUA)  [S6a/S6d]', 322: 'Reset (RSR/RSA)  [S6a/S6d]',
    323: 'Notify (NOR/NOA)  [S6a/S6d]', 324: "ME-Identity-Check (ECR/ECA)  [S13/S13']", 8388620: 'Provide-Location (PLR/PLA)  [SLh]',
    8388621: 'Location-Report (LRR/LRA)  [SLh]', 8388622: 'LCS-Routing-Info (RIR/RIA)  [SLg]', 8388635: 'Spending-Limit (SLR/SLA)  [Sy]',
    8388636: 'Spending-Status-Notification (SNR/SNA)  [Sy]', 8388637: 'TDF-Session (TSR/TSA)  [Sd]', 8388638: 'Update-VCSG-Location (UVR/UVA)  [S7a/S7d]',
    8388639: 'Device-Action (DAR/DAA)  [Tsp]', 8388640: 'Device-Notification (DNR/DNA)  [Tsp]', 8388642: 'Cancel-VCSG-Location (CVR/CVA)  [S7a/S7d]',
    8388731: 'TSSF-Notification (TNR/TNA)  [T4]',
}
BASE_RESULT = {
    1001: 'DIAMETER_MULTI_ROUND_AUTH', 2001: 'DIAMETER_SUCCESS', 2002: 'DIAMETER_LIMITED_SUCCESS',
    3001: 'DIAMETER_COMMAND_UNSUPPORTED', 3002: 'DIAMETER_UNABLE_TO_DELIVER', 3003: 'DIAMETER_REALM_NOT_SERVED',
    3004: 'DIAMETER_TOO_BUSY', 3005: 'DIAMETER_LOOP_DETECTED', 3006: 'DIAMETER_REDIRECT_INDICATION',
    3007: 'DIAMETER_APPLICATION_UNSUPPORTED', 3008: 'DIAMETER_INVALID_HDR_BITS', 3009: 'DIAMETER_INVALID_AVP_BITS',
    3010: 'DIAMETER_UNKNOWN_PEER', 4001: 'DIAMETER_AUTHENTICATION_REJECTED', 4002: 'DIAMETER_OUT_OF_SPACE',
    5001: 'DIAMETER_AVP_UNSUPPORTED', 5002: 'DIAMETER_UNKNOWN_SESSION_ID', 5003: 'DIAMETER_AUTHORIZATION_REJECTED',
    5004: 'DIAMETER_INVALID_AVP_VALUE', 5005: 'DIAMETER_MISSING_AVP', 5006: 'DIAMETER_RESOURCES_EXCEEDED',
    5007: 'DIAMETER_CONTRADICTING_AVPS', 5008: 'DIAMETER_AVP_NOT_ALLOWED', 5009: 'DIAMETER_AVP_OCCURS_TOO_MANY_TIMES',
    5010: 'DIAMETER_NO_COMMON_APPLICATION', 5011: 'DIAMETER_UNSUPPORTED_VERSION', 5012: 'DIAMETER_UNABLE_TO_COMPLY',
    5013: 'DIAMETER_INVALID_BIT_IN_HEADER', 5014: 'DIAMETER_INVALID_AVP_LENGTH', 5015: 'DIAMETER_INVALID_MESSAGE_LENGTH',
    5016: 'DIAMETER_INVALID_AVP_BIT_COMBO', 5017: 'DIAMETER_NO_COMMON_SECURITY',
}
EXP_RESULT = {
    4181: 'DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE', 4182: 'DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT', 5001: 'DIAMETER_ERROR_USER_UNKNOWN',
    5004: 'DIAMETER_ERROR_ROAMING_NOT_ALLOWED', 5420: 'DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION', 5421: 'DIAMETER_ERROR_RAT_NOT_ALLOWED',
    5422: 'DIAMETER_ERROR_EQUIPMENT_UNKNOWN', 5423: 'DIAMETER_ERROR_UNKOWN_SERVING_NODE',
}

# ── The clauses, as algorithms ──────────────────────────────────────────
# RFC 6733 §3 (header) and §4 (AVP).
def hdr_bytes(ver, length, flags, cmd, appid, hbh, e2e):
    return '%02X%06X%02X%06X%08X%08X%08X' % (ver, length, flags, cmd, appid, hbh, e2e)


def msg(flags=0x80, cmd=316, appid=16777251, hbh=1, e2e=2, avps='', ver=1,
        length=None, pad=0):
    body = avps + ('00' * pad)
    n = 20 + len(body) // 2
    return hdr_bytes(ver, n if length is None else length, flags, cmd, appid,
                     hbh, e2e) + body


def avp(code, value='', flags='M', vid=None):
    v = 1 if 'V' in flags else 0
    m = 1 if 'M' in flags else 0
    p = 1 if 'P' in flags else 0
    f = (v << 7) | (m << 6) | (p << 5)
    hdr = 12 if v else 8
    alen = hdr + len(value) // 2
    padn = (4 - alen % 4) % 4
    if v:
        head = '%08X%02X%06X%08X' % (code, f, alen, 10415 if vid is None else vid)
    else:
        head = '%08X%02X%06X' % (code, f, alen)
    return head + value + ('00' * padn)


def u32(n):
    return '%08X' % n


def utf8(s):
    return s.encode().hex().upper()


# ── Driving the module ──────────────────────────────────────────────────
def run(args, module=None):
    mod = module or MODULE
    p = subprocess.run(['bash', mod] + args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def fields(out):
    d = {}
    for line in out.splitlines():
        if '\t' not in line:
            continue
        k, v = line.split('\t', 1)
        d.setdefault(k, v)
    return d


def dec(hexmsg, module=None):
    rc, out, err = run(['--decode-diameter', hexmsg], module)
    return rc, fields(out), err


def norm(s):
    return ' '.join(str(s).split())


def codes_of(out):
    d = out if isinstance(out, dict) else fields(out)
    got = {}
    for k, v in d.items():
        m = re.match(r'avp\.(\d+)\.code$', k)
        if m:
            got[int(m.group(1))] = int(v)
    return got


# ── 1. Header ───────────────────────────────────────────────────────────
def check_header(module=None):
    for flags in (0x00, 0x10, 0x20, 0x40, 0x80, 0xC0, 0xF0):
        for cmd, app in ((316, 16777251), (257, 0), (272, 4), (8388622, 16777255)):
            h = msg(flags=flags, cmd=cmd, appid=app, hbh=0x0A0B0C0D,
                    e2e=0x01020304, avps=avp(263, utf8('x;1;2'), 'M'))
            rc, f, err = dec(h, module)
            case = 'hdr-%02X-%d-%d' % (flags, cmd, app)
            check(case + '-rc', '0', rc, err.strip())
            check(case + '-len', str(20 + len(h) // 2 - 20), f.get('length'),
                  'declared length is the whole message')
            check(case + '-flags', '%02X' % flags, f.get('flags'))
            for bit, name in ((7, 'R'), (6, 'P'), (5, 'E'), (4, 'T')):
                check(case + '-flag_' + name, (flags >> bit) & 1, f.get('flag_' + name))
            check(case + '-cmd', cmd, f.get('command_code'))
            check(case + '-app', app, f.get('application_id'))
            check(case + '-hbh', 0x0A0B0C0D, f.get('hop_by_hop_id'))
            check(case + '-e2e', 0x01020304, f.get('end_to_end_id'))
            check(case + '-hdroct', 20, f.get('header_octets'))
            check(case + '-actual', 20 + len(h) // 2 - 20, f.get('actual_octets'))
            check(case + '-mismatch', 'no', f.get('length_mismatch'))

    # The declared length must agree with the octets present.
    h = msg(avps=avp(263, utf8('x'), 'M'), length=999)
    rc, f, err = dec(h, module)
    check('hdr-length-short', '0', rc)
    check('hdr-length-short-mismatch', 'yes', (f.get('length_mismatch') or '').split(' ')[0])
    h = msg(avps=avp(263, utf8('x') + utf8('y'), 'M'), length=20)
    rc, f, err = dec(h, module)
    check('hdr-length-long-mismatch', 'yes', (f.get('length_mismatch') or '').split(' ')[0])

    # Version 1 only (§3), reserved flag bits zero (§3), 20 octets minimum.
    for ver in (0, 2, 15):
        rc, f, err = dec(msg(ver=ver), module)
        check('hdr-version-%d-refused' % ver, '1', rc)
        check('hdr-version-%d-says-version' % ver, 'yes',
              'yes' if 'version' in err.lower() else 'no', err.strip())
    for flags in (0x01, 0x02, 0x04, 0x08, 0x0F):
        rc, f, err = dec(msg(flags=0x80 | flags), module)
        check('hdr-reserved-%02X-refused' % flags, '1', rc)
        check('hdr-reserved-%02X-says-reserved' % flags, 'yes',
              'yes' if 'reserved' in err.lower() else 'no', err.strip())
    rc, f, err = dec('01000014C0', module)
    check('hdr-too-short', '1', rc)
    rc, f, err = dec('zz', module)
    check('hdr-not-hex', '1', rc)


# ── 2. AVPs ─────────────────────────────────────────────────────────────
def check_avps(module=None):
    # Wire types, flags, padding and the vendor form. `flags` is the octet the
    # module prints (hex), so the clause statement builds the same octet.
    def flagbyte(flags):
        f = 0
        f |= 0x80 if 'V' in flags else 0
        f |= 0x40 if 'M' in flags else 0
        f |= 0x20 if 'P' in flags else 0
        return '%02X' % f

    cases = [
        ('u32', avp(1410, u32(3), 'M'), 1410, 'M', None, u32(3)),
        ('u32-p', avp(1410, u32(3), 'MP'), 1410, 'MP', None, u32(3)),
        ('octet-16', avp(1447, '00' * 16, 'M'), 1447, 'M', None, '00' * 16),
        ('octet-14', avp(1449, '00' * 14, 'M'), 1449, 'M', None, '00' * 14),
        ('utf8', avp(263, utf8('mme;1;2'), 'M'), 263, 'M', None, utf8('mme;1;2')),
        ('vendor', avp(1032, u32(6), 'MV'), 1032, 'MV', 10415, u32(6)),
        ('vendor-other', avp(1032, u32(6), 'MV', vid=99), 1032, 'MV', 99, u32(6)),
        ('base-p', avp(33, 'ABCD', 'MP'), 33, 'MP', None, 'ABCD'),
    ]
    for name, a, code, flags, vid, value in cases:
        h = msg(avps=a)
        rc, f, err = dec(h, module)
        hdrlen = 12 if 'V' in flags else 8
        check('avp-' + name + '-rc', '0', rc, err.strip())
        check('avp-' + name + '-code', code, f.get('avp.0.code'))
        check('avp-' + name + '-flags', flagbyte(flags), f.get('avp.0.flags'))
        check('avp-' + name + '-V', 1 if 'V' in flags else 0, f.get('avp.0.V'))
        check('avp-' + name + '-M', 1 if 'M' in flags else 0, f.get('avp.0.M'))
        check('avp-' + name + '-P', 1 if 'P' in flags else 0, f.get('avp.0.P'))
        check('avp-' + name + '-len', hdrlen + len(value) // 2, f.get('avp.0.length'))
        if vid is not None:
            check('avp-' + name + '-vid', vid, f.get('avp.0.vendor_id'))
        check('avp-' + name + '-dlen', len(value) // 2, f.get('avp.0.data_octets'))
        check('avp-' + name + '-data', value, f.get('avp.0.data'))

    # Several AVPs, with the padding between them stepped over.
    body = avp(263, utf8('a;1;2'), 'M') + avp(1410, u32(2), 'M') + avp(1447, '11' * 16, 'M')
    rc, f, err = dec(msg(avps=body), module)
    check('avps-count', '3', f.get('avp_count'))
    check('avps-0', '263', f.get('avp.0.code'))
    check('avps-1', '1410', f.get('avp.1.code'))
    check('avps-2', '1447', f.get('avp.2.code'))
    check('avps-last-data', '11' * 16, f.get('avp.2.data'))

    # Refusals: a declared length below 8, past the end, shorter than the
    # vendor header, and a fragment left over after the last AVP.
    for name, h in (
            ('len-below-8', msg(avps='%08X%02X000007' % (1410, 0x40))),
            ('overrun', msg(avps='%08X%02X0000FF' % (1410, 0x40))),
            ('v-without-vendor', msg(avps='%08X%02X00000C' % (1410, 0xC0))),
            ('leftover', msg(avps=avp(1410, u32(1), 'M') + 'FFFF')),
            ('zero-length', msg(avps='%08X%02X000000' % (1410, 0x40)))):
        rc, f, err = dec(h, module)
        check('avp-' + name + '-refused', '1', rc, err.strip())

    # Typed renderings. Each is its own message, so index 0 is the AVP.
    typed = [
        (avp(263, utf8('mme.local;0001;0002'), 'M'), 'Session-Id=mme.local;0001;0002'),
        (avp(1, utf8('310150123456789'), 'M'), 'User-Name=310150123456789'),
        (avp(1407, '02F810', 'M'), 'Visited-PLMN-Id=208-01'),
        (avp(1407, '130062', 'M'), 'Visited-PLMN-Id=310-260'),
        (avp(1407, '13F620', 'M'), 'Visited-PLMN-Id=316-02'),
        (avp(1405, u32(0x00000013), 'M'), 'ULR-Flags=19'),
        (avp(1406, u32(0x00000001), 'M'), 'ULA-Flags=1'),
        (avp(1410, u32(2), 'M'), 'Number-Of-Requested-Vectors=2'),
        (avp(1412, u32(0), 'M'), 'Immediate-Response-Preferred=0'),
        (avp(1417, u32(6), 'M'), 'Network-Access-Mode=6'),
        (avp(1420, u32(0), 'M'), 'Cancellation-Type=0'),
        (avp(1424, u32(0), 'M'), 'Subscriber-Status=0'),
        (avp(1447, '00' * 16, 'M'), 'RAND=' + '00' * 16),
        (avp(1449, '00' * 16, 'M'), 'AUTN=' + '00' * 16),
        (avp(1450, '00' * 16, 'M'), 'KASME=' + '00' * 16),
        (avp(1032, u32(6), 'MV'), 'RAT-Type=6'),
        (avp(268, u32(2001), 'M'), 'Result-Code=DIAMETER_SUCCESS (2001)'),
        (avp(268, u32(5001), 'M'), 'Result-Code=DIAMETER_AVP_UNSUPPORTED (5001)'),
        (avp(298, u32(5001), 'M'), 'Experimental-Result-Code=DIAMETER_ERROR_USER_UNKNOWN (5001)'),
        (avp(298, u32(5420), 'M'), 'Experimental-Result-Code=DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (5420)'),
        (avp(298, u32(5004), 'M'), 'Experimental-Result-Code=DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004)'),
        (avp(297, avp(298, u32(5421), 'M'), 'M'), 'Experimental-Result (grouped)'),
        (avp(277, u32(0), 'M'), 'Auth-Session-State=NO_STATE_MAINTAINED (0)'),
        (avp(277, u32(1), 'M'), 'Auth-Session-State=value 00000001'),
        (avp(1408, avp(1410, u32(2), 'M') + avp(1412, u32(0), 'M'), 'M'),
         'Requested-EUTRAN-Authentication-Info (grouped)'),
        (avp(1414, avp(1447, '00' * 16, 'M'), 'M'), 'E-UTRAN-Vector (grouped)'),
    ]
    for n, (a, want) in enumerate(typed):
        rc, f, err = dec(msg(avps=a), module)
        check('typed-%d-%s' % (n, want.split('=')[0].split(' ')[0]), want,
              f.get('avp.0.decoded'))


# ── 3. The registries ───────────────────────────────────────────────────
def check_registries(module=None):
    base = dict(BASE_AVPS)
    base[1032] = 'RAT-Type'
    allavps = dict(base)
    allavps.update(TGPP_AVPS)
    codes = sorted(allavps)
    # 20 AVPs per message: the walk reports avp.N.name for each.
    for i in range(0, len(codes), 20):
        batch = codes[i:i + 20]
        h = msg(avps=''.join(avp(c, '00' * 4, 'MV') for c in batch))
        rc, f, err = dec(h, module)
        if rc != 0:
            fail('reg-batch-%d-rc' % i, '0', rc, err.strip())
            continue
        for j, c in enumerate(batch):
            check('reg-avp-%d' % c, allavps[c], f.get('avp.%d.name' % j))
    for c in (6, 12, 1100, 1399, 2000, 2):
        rc, f, err = dec(msg(avps=avp(c, '00000000', 'M')), module)
        check('reg-avp-unknown-%d' % c, 'unknown AVP code %d' % c, f.get('avp.0.name'))

    for app, name in sorted(APPS.items()):
        rc, f, err = dec(msg(appid=app), module)
        check('reg-app-%d' % app, norm(name), norm(f.get('application_name')))
    for app in (16777227, 16777399, 424242):
        rc, f, err = dec(msg(appid=app), module)
        check('reg-app-unknown-%d' % app, 'unknown', f.get('application_name'))

    for cmd, name in sorted(COMMANDS.items()):
        rc, f, err = dec(msg(cmd=cmd), module)
        got = norm(f.get('command_name'))
        check('reg-cmd-%d' % cmd, norm(name).split(' [')[0], got.split(' [')[0])
    for cmd in (999, 0, 314, 315):
        rc, f, err = dec(msg(cmd=cmd), module)
        check('reg-cmd-unknown-%d' % cmd, 'unassigned/unknown', f.get('command_name'))

    # Result codes through the AVP the code travels in.
    for code, name in sorted(BASE_RESULT.items()):
        rc, f, err = dec(msg(avps=avp(268, u32(code), 'M')), module)
        check('reg-rc-%d' % code, 'Result-Code=%s (%d)' % (name, code), f.get('avp.0.decoded'))
    for code, name in sorted(EXP_RESULT.items()):
        rc, f, err = dec(msg(avps=avp(298, u32(code), 'M')), module)
        check('reg-erc-%d' % code,
              'Experimental-Result-Code=%s (%d)' % (name, code), f.get('avp.0.decoded'))


# ── 4. The forged messages ──────────────────────────────────────────────
def check_builders(module=None):
    # §7.2.3/§7.2.5/§7.2.7: the AVPs the MME must put in each request.
    air_required = {263: 'Session-Id', 1: 'User-Name', 1407: 'Visited-PLMN-Id',
                    1408: 'Requested-EUTRAN-Authentication-Info', 277: 'Auth-Session-State',
                    264: 'Origin-Host', 296: 'Origin-Realm', 283: 'Destination-Realm'}
    ulr_required = {263: 'Session-Id', 1: 'User-Name', 1407: 'Visited-PLMN-Id',
                    1405: 'ULR-Flags', 1032: 'RAT-Type', 277: 'Auth-Session-State',
                    264: 'Origin-Host', 296: 'Origin-Realm', 283: 'Destination-Realm'}
    clr_required = {263: 'Session-Id', 1: 'User-Name', 1420: 'Cancellation-Type',
                    277: 'Auth-Session-State', 264: 'Origin-Host', 296: 'Origin-Realm',
                    283: 'Destination-Realm'}
    for verb, cmd, required, extra in (
            ('--build-air', 318, air_required, {'1408': (1410, 1412)}),
            ('--build-ulr', 316, ulr_required, {}),
            ('--build-clr', 317, clr_required, {})):
        rc, out, err = run([verb, '310150123456789'], module)
        case = verb.lstrip('-')
        check(case + '-rc', '0', rc, err.strip())
        f = fields(out)
        hexmsg = f.get('hex')
        if not hexmsg:
            fail(case + '-hex', 'present', 'absent')
            continue
        rc2, d, err2 = dec(hexmsg, module)
        check(case + '-decodes', '0', rc2, err2.strip())
        check(case + '-cmd', cmd, d.get('command_code'))
        check(case + '-app', 16777251, d.get('application_id'))
        check(case + '-R', '1', d.get('flag_R'))
        check(case + '-length-ok', 'no', d.get('length_mismatch'))
        got = codes_of(fields(run(['--decode-diameter', hexmsg], module)[1]))
        present = set(got.values())
        for c, name in sorted(required.items()):
            check('%s-has-%d' % (case, c), True, c in present, 'AVP %s' % name)
        if verb == '--build-ulr':
            # RAT-Type is a vendor-specific AVP (TS 29.212 code 1032).
            idx = [i for i, v in got.items() if v == 1032]
            if not idx:
                fail('ulr-1032', 'present', 'absent')
            else:
                check('ulr-1032-vendor', '10415', fields(run(['--decode-diameter', hexmsg], module)[1]).get('avp.%d.vendor_id' % idx[0]))
                check('ulr-1032-decoded', 'RAT-Type=6',
                      fields(run(['--decode-diameter', hexmsg], module)[1]).get('avp.%d.decoded' % idx[0]))
            check('ulr-flags-name', 'ULR-Flags',
                  fields(run(['--decode-diameter', hexmsg], module)[1]).get('avp.%d.name' % [i for i, v in got.items() if v == 1405][0]) if 1405 in present else '')
        # The module's own round-trip fields must agree with the frame.
        check(case + '-rt-cmd', cmd, f.get('roundtrip_command'))
        check(case + '-rt-app', 16777251, f.get('roundtrip_app'))


# ── 5. Wireshark as the second implementation ───────────────────────────
def check_tshark(module=None):
    if not shutil.which(TSHARK) or not shutil.which('text2pcap'):
        note('tshark/text2pcap not installed; the Wireshark cross-check is skipped')
        return
    frames = []
    for verb, cmd in (('--build-air', 318), ('--build-ulr', 316),
                      ('--build-clr', 317)):
        out = run([verb, '310150123456789'], module)[1]
        h = fields(out).get('hex')
        if not h:
            fail('tshark-' + verb + '-hex', 'present', 'absent')
            continue
        frames.append((verb.lstrip('-'), cmd, h))
    with tempfile.TemporaryDirectory() as td:
        for name, cmd, h in frames:
            hx = os.path.join(td, name + '.hex')
            pc = os.path.join(td, name + '.pcap')
            dump = []
            for i in range(0, len(h), 16):
                dump.append('%06x  %s' % (i, ' '.join(
                    h[j:j + 2] for j in range(i * 2, min(i * 2 + 32, len(h)), 2))))
            open(hx, 'w').write('\n'.join(dump) + '\n')
            p = subprocess.run(['text2pcap', '-q', '-T', '3868,3868', hx, pc],
                               capture_output=True, text=True)
            if p.returncode != 0:
                fail('tshark-' + name + '-text2pcap', '0', p.returncode, p.stderr.strip()[:120])
                continue
            p = subprocess.run([TSHARK, '-r', pc, '-d', 'tcp.port==3868,diameter',
                                '-T', 'fields', '-e', 'diameter.cmd.code',
                                '-e', 'diameter.applicationId',
                                '-e', 'diameter.avp.code'],
                               capture_output=True, text=True)
            rows = [r for r in p.stdout.splitlines() if r.strip()]
            if not rows:
                fail('tshark-' + name + '-dissected', 'a Diameter frame', 'nothing',
                     p.stderr.strip()[:120])
                continue
            cells = rows[0].split('\t')
            check('tshark-' + name + '-cmd', (int(cells[0]) if cells[0] else None), cmd)
            check('tshark-' + name + '-app', 16777251,
                  int(cells[1]) if len(cells) > 1 and cells[1] else None)
            ws = [int(x) for c in cells[2:] for x in c.split(',') if x.strip()]
            mine = codes_of(fields(run(['--decode-diameter', h], module)[1]))
            check('tshark-' + name + '-avps', [mine[k] for k in sorted(mine)], ws)


# ── 6. The Wireshark dictionary, as a second name table ─────────────────
def check_dictionary(module=None):
    path = os.path.join(WIRESHARK_DIR, 'dictionary.xml')
    if not os.path.exists(path):
        note('Wireshark dictionary not found; the name cross-check is skipped')
        return
    text = open(path, encoding='utf-8', errors='replace').read()
    # Wireshark states base AVPs in dictionary.xml and 3GPP AVPs in the
    # same file with vendor-id="TGPP"; it does not split by application.
    rows = re.findall(r'<avp name="([^"]+)" code="(\d+)"[^>]*vendor-bit="must"[^>]*vendor-id="TGPP"', text)
    ws = {}
    for name, code in rows:
        ws.setdefault(int(code), name)
    agree = 0
    for code, name in sorted(TGPP_AVPS.items()):
        if code in ws:
            if ws[code] == name:
                agree += 1
            else:
                note('Wireshark reads 3GPP AVP %d as %s, the clause as %s'
                     % (code, ws[code], name))
    check('tshark-dict-agrees', 'yes', 'yes' if agree else 'no',
          '%d of %d 3GPP codes agree with the clause' % (agree, len(TGPP_AVPS)))


# ── negctl: reintroduce the defects the check must catch ────────────────
MUTANTS = [
    ('origin-realm-at-285',
     '        296)     echo "Origin-Realm" ;;',
     '        285)     echo "Origin-Realm" ;;'),
    ('command-268-read-as-credit-control',
     '        268)       echo "Diameter-EAP (DER/DEA)" ;;',
     '        268)       echo "Credit-Control (CCR/CCA)" ;;'),
    ('app-s13-read-as-slg',
     "        16777252)  echo \"3GPP S13/S13'\" ;;",
     "        16777252)  echo \"3GPP SLg\" ;;")
    ,
    ('experimental-result-read-as-base',
     '''            298) printf 'avp.%d.decoded\\tExperimental-Result-Code=%s\\n' "$n" \\
                     "$(lcore_diameter_exp_result_code "$(( 16#${data:0:8} ))")" ;;''',
     '''            298) printf 'avp.%d.decoded\\tExperimental-Result-Code=%s\\n' "$n" \\
                     "$(lcore_diameter_result_code "$(( 16#${data:0:8} ))")" ;;'''),
    ('visited-plmn-read-as-raw-hex',
     '''            1407) printf 'avp.%d.decoded\\tVisited-PLMN-Id=%s\\n' "$n" \\
                     "$(lcore_plmn_from_octets "$data")" ;;''',
     '''            1407) printf 'avp.%d.decoded\\tVisited-PLMN-Id=%s\\n' "$n" \\
                     "$data" ;;'''),
]


def negctl():
    global MISMATCHES
    src = open(MODULE).read()
    if not os.path.exists('/tmp'):
        print('SKIP negctl: no /tmp')
        return 2
    scratch = '/tmp/lcore_negctl_%d.sh' % os.getpid()
    caught = 0
    for name, old, new in MUTANTS:
        if old not in src:
            print('NEGCTL\t%s\tANCHOR MISSING' % name)
            continue
        open(scratch, 'w').write(src.replace(old, new, 1))
        before = MISMATCHES
        try:
            check_header(scratch)
            check_avps(scratch)
            check_registries(scratch)
            check_builders(scratch)
        except Exception as exc:  # a mutant that breaks the parser outright is caught too
            print('NEGCTL\t%s\tCAUGHT (exception: %s)' % (name, exc))
            caught += 1
            MISMATCHES = before
            continue
        delta = MISMATCHES - before
        MISMATCHES = before
        if delta:
            caught += 1
            print('NEGCTL\t%s\tCAUGHT (%d mismatches)' % (name, delta))
        else:
            print('NEGCTL\t%s\tMISSED' % name)
    try:
        os.unlink(scratch)
    except OSError:
        pass
    return 0 if caught == len(MUTANTS) else 1


def main(argv):
    global VERBOSE
    module = None
    only = None
    want_neg = False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ('-v', '--verbose'):
            VERBOSE = True
        elif a == '--negctl':
            want_neg = True
        elif a == '--module':
            i += 1
            module = argv[i]
        elif a == '--only':
            i += 1
            only = argv[i]
        elif a in ('-h', '--help'):
            print('usage: check_diameter_codec.py [-v] [--negctl] [--module PATH] [--only NAME]')
            return 0
        else:
            print('ERROR\tunknown argument %s' % a, file=sys.stderr)
            return 2
        i += 1
    if not os.path.exists(module or MODULE):
        print('ERROR\tmodule not found: %s' % (module or MODULE), file=sys.stderr)
        return 2
    if want_neg:
        return negctl()
    sections = [('header', check_header), ('avps', check_avps),
                ('registries', check_registries), ('builders', check_builders),
                ('tshark', check_tshark), ('dictionary', check_dictionary)]
    if only:
        sections = [s for s in sections if s[0] == only]
        if not sections:
            print('ERROR\tno such section: %s' % only, file=sys.stderr)
            return 2
    for name, fn in sections:
        try:
            fn(module)
        except Exception as exc:
            fail(name + '-exception', 'no exception', repr(exc))
    print('CASES\t%d' % CASES)
    print('MISMATCHES\t%d' % MISMATCHES)
    for case, want, got, why in FAILURES[:40]:
        print('FAIL\t%s\twant=%r got=%r\t%s' % (case, want, got, why))
    print('RESULT\t%s' % ('PASS' if MISMATCHES == 0 else 'FAIL'))
    return 0 if MISMATCHES == 0 else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
