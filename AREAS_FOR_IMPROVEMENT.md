# Areas for Improvement: Lucid Vigil

*Generated on: 2025-08-19*

This document outlines key architectural recommendations to enhance the scalability, resilience, and enterprise-readiness of the Lucid Vigil agent. The suggestions are based on a review of the codebase at the time of generation.

## Files Reviewed

The following files and directories were analyzed to form these recommendations:

-   `pkg/actions/**`
-   `pkg/api/**`
-   `pkg/config/enhanced_config.go`
-   `pkg/enhanced/**`
-   `pkg/errors/monitor_errors.go`
-   `pkg/events/**`
-   `pkg/scheduler/**`

## Architectural Recommendations for Enterprise Scalability

### 1. Decouple Components with an External Message Bus

**Problem:** The current `EventBus` is an in-memory component. This creates a single point of failure, prevents multi-node scalability, and loses all event data if the agent restarts.

**Recommendation:**
Replace the in-memory `EventBus` with a robust, external message queue or streaming platform like **NATS**, **Kafka**, or **RabbitMQ**.

-   **Scalability:** Allow multiple agent instances to communicate through a central bus, enabling distributed and specialized workloads.
-   **Resilience:** Gain event persistence, ensuring that events are not lost if a component crashes and can be processed upon restart.
-   **Decoupling:** Truly decouple monitors from handlers, allowing components to operate and scale independently.

### 2. Externalize State Management

**Problem:** Critical state, such as the `CorrelationEngine`'s recent event window and the `EnhancedSentryMonitor`'s file integrity baseline, is stored in-memory. This state is volatile and lost on restart, making the system fragile and blind to long-term threats.

**Recommendation:**
Use an external, high-speed data store like **Redis** to manage this state.

-   **Correlation Engine:** Store event windows and correlation state in Redis to enable persistence and shared state across multiple engine instances.
-   **Sentry Monitor:** Persist the file integrity baseline in Redis or a local database (e.g., BoltDB) to ensure continuity of monitoring across agent restarts.

### 3. Enhance the Management API

**Problem:** The current API is minimal, offering only basic health checks. An enterprise product requires a comprehensive API for management, operations, and integration.

**Recommendation:**
Develop a full-featured RESTful or gRPC API with robust security and expanded capabilities.

-   **Security:** Implement strong authentication and authorization (e.g., API keys, mTLS, JWT) for all endpoints.
-   **Dynamic Configuration:** Add endpoints to view and dynamically update monitor configurations without requiring an agent restart (e.g., `PUT /api/v1/monitors/sentry/config`).
-   **Operational Control:** Provide endpoints to get the status of monitors, view live event streams (via WebSockets), and access detailed system metrics.
-   **Action Management:** Create endpoints to manage the state of defensive actions, such as listing blocked IPs and providing a mechanism to reverse actions (`DELETE /api/v1/actions/block_ip/entries/{ip}`).

### 4. Improve Action Execution and Safety

**Problem:** Actions directly execute privileged commands like `sudo iptables`. This approach is insecure, not easily portable across different OS environments, and lacks state management.

**Recommendation:**

-   **Abstract Host Interactions:** Create an abstraction layer for host interactions (e.g., a `FirewallManager` interface) with specific implementations for different operating systems (`iptables`, `pf`, Windows Firewall).
-   **Eliminate `sudo` Requirement:** Avoid running the entire agent as root. Use Linux Capabilities (`CAP_NET_ADMIN`) to grant only necessary permissions, or use a small, privileged helper process for tasks that require elevation.
-   **Track Action State:** Record the state of all actions taken (e.g., blocked IPs, killed PIDs) in a persistent store like Redis for auditing and reversal capabilities.

### 5. Refine the Scheduler and Concurrency Model

**Problem:** The current scheduler uses a simple "one goroutine per monitor" model. This can be inefficient and lead to resource exhaustion if the number of monitors grows significantly.

**Recommendation:**
Evolve the scheduler to use a **worker pool pattern**.

-   **Resource Efficiency:** A fixed pool of worker goroutines can execute tasks from a central queue, providing better control over CPU and memory consumption.
-   **Advanced Scheduling:** This architecture facilitates more advanced features, such as dynamic scheduling (adjusting frequency based on threat level), setting monitor priorities, and handling dependencies between monitor runs.

------------------------------------

### Additional Still Missing (Recommendations):

-   **Event Persistence:** Consider adding database storage for events
-   **Dead Letter Queue:** Handle permanently failed events
-   **Circuit Breakers:** Protect against cascading failures
-   **Metrics Export:** Integrate with monitoring systems (Prometheus, etc.)
-   **Configuration Validation:** Validate monitor configs at startup
-   **Event Routing:** More sophisticated event routing based on rules

