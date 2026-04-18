#pragma once

// ═══════════════════════════════════════════════════════════════════════════════
//  Aegis-CPP — A comprehensive C++17 Access Control Library
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Core headers:
//    Aegis/Permission.h     - Permission enum and string-based permissions
//    Aegis/Role.h           - Role class with inheritance and deny rules
//    Aegis/User.h           - User class with metadata
//    Aegis/Resource.h       - Resource-scoped permissions
//    Aegis/Policy.h         - Condition-based policy engine (ABAC)
//    Aegis/AuditLog.h       - Audit trail for all access decisions
//    Aegis/AccessControl.h  - Core ACL engine
//    Aegis/Serializer.h     - JSON export/import
//    Aegis/ThreadSafe.h     - Thread-safe wrapper
//
// ═══════════════════════════════════════════════════════════════════════════════

#include "Aegis/Permission.h"
#include "Aegis/Role.h"
#include "Aegis/User.h"
#include "Aegis/Resource.h"
#include "Aegis/Policy.h"
#include "Aegis/AuditLog.h"
#include "Aegis/AccessControl.h"
#include "Aegis/Serializer.h"
#include "Aegis/ThreadSafe.h"
