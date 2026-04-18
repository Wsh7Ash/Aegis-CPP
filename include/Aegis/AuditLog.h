#pragma once
#include "Permission.h"
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <functional>

namespace Aegis {

enum class AuditAction {
    PermissionCheck, RoleAssigned, RoleRevoked,
    UserCreated, UserDeleted, UserDeactivated,
    PolicyEvaluated, ResourceAccess, Custom,
};

inline const char* auditActionToString(AuditAction a) {
    switch (a) {
        case AuditAction::PermissionCheck:  return "PERMISSION_CHECK";
        case AuditAction::RoleAssigned:     return "ROLE_ASSIGNED";
        case AuditAction::RoleRevoked:      return "ROLE_REVOKED";
        case AuditAction::UserCreated:      return "USER_CREATED";
        case AuditAction::UserDeleted:      return "USER_DELETED";
        case AuditAction::UserDeactivated:  return "USER_DEACTIVATED";
        case AuditAction::PolicyEvaluated:  return "POLICY_EVALUATED";
        case AuditAction::ResourceAccess:   return "RESOURCE_ACCESS";
        case AuditAction::Custom:           return "CUSTOM";
    }
    return "UNKNOWN";
}

struct AuditEntry {
    std::chrono::system_clock::time_point timestamp;
    AuditAction action;
    int userId;
    std::string detail;
    bool result;

    std::string toString() const {
        auto t = std::chrono::system_clock::to_time_t(timestamp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ")
            << " | " << auditActionToString(action)
            << " | user=" << userId
            << " | " << (result ? "GRANTED" : "DENIED")
            << " | " << detail;
        return oss.str();
    }
};

class AuditLog {
public:
    using Callback = std::function<void(const AuditEntry&)>;

    void log(AuditAction action, int userId, const std::string& detail, bool result) {
        AuditEntry entry{ std::chrono::system_clock::now(), action, userId, detail, result };
        m_entries.push_back(entry);
        if (m_callback) m_callback(entry);
    }

    void setCallback(Callback cb) { m_callback = std::move(cb); }
    const std::vector<AuditEntry>& getEntries() const { return m_entries; }

    std::vector<AuditEntry> getEntriesForUser(int userId) const {
        std::vector<AuditEntry> r;
        for (auto& e : m_entries) if (e.userId == userId) r.push_back(e);
        return r;
    }

    std::vector<AuditEntry> getDenials() const {
        std::vector<AuditEntry> r;
        for (auto& e : m_entries) if (!e.result) r.push_back(e);
        return r;
    }

    size_t size() const { return m_entries.size(); }
    void clear() { m_entries.clear(); }

private:
    std::vector<AuditEntry> m_entries;
    Callback m_callback;
};

} // namespace Aegis
