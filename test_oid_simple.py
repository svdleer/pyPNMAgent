#!/usr/bin/env python3
"""
Simple SNMP OID index test - matches agent.py code exactly
Run: source /home/svdleer/scripts/python/venv/bin/activate && python3 test_oid_simple.py
"""

import asyncio

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, bulk_walk_cmd
    )
    PYSNMP_V7 = True
except ImportError:
    print("pysnmp v7 not available, skipping test")
    exit(1)

CMTS_IP = "172.16.6.212"
COMMUNITY = "Z1gg0@LL"

async def walk_oid(oid, limit=10):
    """Walk OID exactly like agent does"""
    results = []
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            SnmpEngine(),
            CommunityData(COMMUNITY),
            await UdpTransportTarget.create((CMTS_IP, 161), timeout=10, retries=2),
            ContextData(),
            0, 50,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication or errorStatus:
                print(f"  Error: {errorIndication or errorStatus}")
                break
            for varBind in varBinds:
                oid_str = str(varBind[0])
                index = oid_str.split('.')[-1]  # LAST component only
                full_suffix = '.'.join(oid_str.split('.')[len(oid.split('.')):])  # Full suffix after base OID
                value = varBind[1]
                results.append((index, full_suffix, value))
                if len(results) >= limit:
                    return results
    except Exception as e:
        print(f"  Exception: {e}")
    return results

async def main():
    print("="*70)
    print("SNMP OID Index Test - Exactly Like Agent")
    print("="*70)
    
    # Test OIDs
    oid_mac = '1.3.6.1.4.1.4491.2.1.20.1.3.1.2'
    oid_md_if = '1.3.6.1.4.1.4491.2.1.20.1.3.1.5'
    oid_us_ch = '1.3.6.1.4.1.4491.2.1.20.1.4.1.3'
    
    print("\n1. MAC addresses (docsIf3CmtsCmRegStatusMacAddr)")
    mac_results = await walk_oid(oid_mac, limit=5)
    print(f"   Found: {len(mac_results)}")
    for idx, suffix, val in mac_results[:3]:
        print(f"   Index={idx:6s} Suffix={suffix:30s} Value={val.prettyPrint()[:40]}")
    
    print("\n2. MD-IF-INDEX (docsIf3CmtsCmRegStatusMdIfIndex)")
    md_results = await walk_oid(oid_md_if, limit=5)
    print(f"   Found: {len(md_results)}")
    for idx, suffix, val in md_results[:3]:
        print(f"   Index={idx:6s} Suffix={suffix:30s} Value={val}")
    
    print("\n3. US Channel (docsIf3CmtsCmUsStatusChIfIndex)")
    us_results = await walk_oid(oid_us_ch, limit=5)
    print(f"   Found: {len(us_results)}")
    for idx, suffix, val in us_results[:3]:
        print(f"   Index={idx:6s} Suffix={suffix:30s} Value={val}")
    
    # Analysis
    print("\n" + "="*70)
    print("INDEX COMPARISON")
    print("="*70)
    
    mac_last = {r[0] for r in mac_results}
    md_last = {r[0] for r in md_results}
    us_last = {r[0] for r in us_results}
    
    mac_suffix = {r[1] for r in mac_results}
    md_suffix = {r[1] for r in md_results}
    us_suffix = {r[1] for r in us_results}
    
    print(f"\nLast component indexes:")
    print(f"  MAC:    {sorted(mac_last)}")
    print(f"  MD-IF:  {sorted(md_last)}")
    print(f"  US-CH:  {sorted(us_last)}")
    
    print(f"\nFull suffix indexes:")
    print(f"  MAC:    {sorted(mac_suffix)}")
    print(f"  MD-IF:  {sorted(md_suffix)}")
    print(f"  US-CH:  {sorted(us_suffix)}")
    
    print(f"\nMatches (last component):")
    print(f"  MAC ∩ MD-IF: {sorted(mac_last & md_last)}")
    print(f"  MAC ∩ US-CH: {sorted(mac_last & us_last)}")
    
    print(f"\nMatches (full suffix):")
    print(f"  MAC ∩ MD-IF: {sorted(mac_suffix & md_suffix)}")
    print(f"  MAC ∩ US-CH: {sorted(mac_suffix & us_suffix)}")
    
    if not (mac_last & md_last) and not (mac_last & us_last):
        print("\n⚠️  NO MATCHES using last component!")
        print("    Need to use full suffix for index matching")
    else:
        print("\n✓ Matches found!")

if __name__ == "__main__":
    asyncio.run(main())
