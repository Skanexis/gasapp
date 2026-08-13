---
name: tasks-aegis-core
description: Task list for implementing aegis-core facade and orchestration layer
metadata:
  type: project
---

## Aegis-Core Implementation Tasks

Based on AEGIS_MASTER_PLAN.md section 9.3 and 9.4, implement the aegis-core crate which serves as the facade/orchestration layer between the protocol layer and the FFI layer.

### Core Responsibilities:
- State management and event orchestration
- Queues, retries, reaction to events
- Export event stream for UI via FFI
- Handle SecurityAlert for Security Center
- Implement AegisClient FFI interface

### Tasks:

1. **Define core state structures** - Design the core state machine that tracks sessions, identities, etc.
2. **Implement event handling system** - Create the AegisEvent enum and event processing loop
3. **Implement FFI interface methods** - Implement all methods from the AegisClient interface:
   - unlock/lock/state lifecycle methods
   - Identity management (create_identity, restore_from_recovery, generate_recovery_key)
   - Chat and message operations (list_chats, list_messages, send_message, set_disappearing_timer)
   - Security functions (safety_number, mark_verified, security_status, linked_devices, revoke_device)
   - Device linking (start_device_linking, approve_linking)
   - Backup operations (run_backup, backup_status)
   - Event listener management (set_event_listener)

4. **Implement security alert processing** - Handle the SecurityAlert enum and feed to Security Center
5. **Add proper error handling** - Map internal errors to FfiError types appropriately
6. **Add state persistence** - Integrate with aegis-storage for saving/loading state
7. **Add background task management** - Handle network retries, sync progress, etc.
8. **Add testing** - Unit tests for all core functionality
9. **Add FFI safety** - Ensure no secret material leaks through FFI boundary
10. **Integrate with protocol layer** - Connect to aegis-protocol via ProtocolEngine trait

### Dependencies:
- aegis-types (for IDs, Secret types, etc.)
- aegis-protocol (for ProtocolEngine, Fingerprint, SafetyNumber, etc.)
- aegis-storage (for persistence)
- aegis-keystore (for key management)
- aegis-net (for network operations)
- aegis-media (for attachments)

### Current Status:
- [ ] Create all crates with skeleton (M0) - DONE
- [ ] �� 🔐 Implement Secret<T> + newtype-обёртки in aegis-types (M1) - DONE
- [ ] �� 🔐 Determine ProtocolEngine trait (M1) - DONE
- [ ] Define aegis.udl - full FFI contract (M1) - PARTIAL (from plan)
- [ ] �� 🔐 Implement aegis-protocol: PQXDH (M2)
- [ ] �� 🔐 Implement aegis-protocol: Double Ratchet (M2)
- [ ] �� 🔐 Implement aegis-protocol: fingerprint / safety numbers (M2) - DONE
- [ ] �� 🔐 Implement aegis-protocol: Sender Keys (M5)
- [ ] �� 🔐 Implement aegis-protocol: SPQR (M7 or v1.1)
- [ ] �� 🔐 Implement aegis-keystore (M2)
- [ ] Implement aegis-storage with schema and migrations (M3)
- [ ] Implement aegis-net (M3)
- [ ] Implement aegis-media (M5)
- [ ] Implement aegis-backup (M6)
- [ ] �� 🔐 Implement aegis-core (M3) - CURRENT TARGET

### Immediate Next Steps:
1. Define core data structures for aegis-core
2. Implement the FFI interface methods stubs
3. Set up event handling system
4. Connect to storage and protocol layers