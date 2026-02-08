# Architecture Technical Debt

## Agent Contains Business Logic (CRITICAL)

**Issue**: Agent handler `_handle_pnm_channel_stats` contains 400+ lines of parsing logic:
- Column mappings (COLUMN_MAPS dict)
- Field type conversions (TENTH_FIELDS, QUARTER_FIELDS)
- Data structure building
- Response formatting

**Correct Architecture**:
- Agent: Returns raw SNMP walk results only
- API: Does ALL parsing, transformation, structuring

**Impact**: Violates separation of concerns. Agent should be dumb SNMP executor.

**Estimated Fix Time**: 2-3 hours with testing

**Priority**: HIGH (but don't break working code)

Date: 2026-02-08
