# Gemini Default Settings

## Overview

You are assisting a senior full-stack engineer launching a cybersecurity software business on his personal machine.
Organization is key to making sure our goals are scoped and executed properly.

## Request Classification
When a new request is received, clarification on it should be requested. Specifically, is this a general request for information, an existing project related request, or the beginning of a potential new project.

## Current Projects

### 1. Debt Lucidity Solutions
- **Goal:** A scalable cloud-based debt collection software.
- **GitHub Repositories:**
    - **UI:** TBD
    - **API:** TBD
- **Status:** Prototype In-Progress
    - **UI:**
        - **Status:** Scaffolding in-progress.
        - **Details:** Initial routing with Tanstack setup (one route).
        - **Blocked by:** API development.
    - **API:**
        - **Status:** Prototype in-progress.
        - **Details:** Defining Types, Controllers, Services, Entities, Roles, and Modules for basic CRUD.
        - **Next Steps:** Implement complex business logic after CRUD is functional.
- **Documentation:** TBD
- **Tech Stack:**
    - **UI:** React (TypeScript), Vite, Tailwind (v.4), TanStack Router
    - **API:** NestJS (TypeScript)
    - **Database:** Postgres
    - **Cache:** Redis
    - **Authentication:** JSON Web Tokens with RBAC

### 2. Lucid Vigil
- **Goal:** A cloud-based cybersecurity software that uses a sophisticated approach in detecting, analyzing, and protecting local machines and cloud systems from bad actors, malware, and potential threats.
- **GitHub Repositories:**
    - **UI:** TBD
    - **API:** TBD
- **High-Level Plan:** Uses 5 Monitor Classes.
    1.  **Sentry:** Guards high-value and high-risk targets. Reports regularly on status and proactively attacks threats.
    2.  **Sentinel:** Guards the entire system by monitoring and reporting on different processes (CPU temp, process count, certificate threats, exfiltration, etc.). Reports regularly on each aspect and proactively attacks threats.
    3.  **Detectors:** Observers that log system activity and use machine-learning to create baselines for what is normal and abnormal. Detects threats as soon as possible and flags them for immediate action.
    4.  **Analyzers:** Reviews logs and current system status to determine what is causing the potential issue or known issues. Attempts to categorize them by type, looks for historical patterns, attempts to find the source, and crafts a strategy for containment.
    5.  **Scribes:** Would be in charge of crafting legally-sound forensic documentation for legal cases to use in proving the source and actions taken by bad actors. Generating non-technical and technical reports for each incident.
- **Documentation:** TBD
- **Tech Stack:**
    - **Customer UI:** React, Vite, Tailwind (v.4), TanStack Router
    - **Admin UI:** React, Vite, Tailwind (v.4), TanStack Router
    - **Centralized Logging:** Victorialogs
    - **Cloud Architecture:** Kubernetes
    - **Monitor API:** Golang, Rust, and Python.

## Default Tech Choices
- **Default Web API:** NestJS (TypeScript)
- **Default UI:** React w/ TypesScript, Vite, Tailwind v.4, TanStack Router
- **Default SQL DB:** Postgres
- **Default NoSQL DB:** Mongo
- **Default Cache:** Redis
- **Default Cloud Architecture:** Kubernetes
- **Default Reverse-Proxy:** Nginx
- **Default Authentication:** JSON Webtokens with Role based access (RBAC)
- **Command Line Tools:** Golang for production-grade code. Python for experimentation/exploration.
- **Optimization Concerns:** When code needs to be as efficient as possible, consider Java and Rust.

## Engineering Standards
- Cloud-native microservices (Kubernetes: GCP, AWS, DigitalOcean).
- Normalized SQL databases.
- **Preferred stack:** JavaScript (React, Node.js, Express, NestJS), Python, Golang, Java.
- **Tools:** GitHub, Git, CI/CD, Redis, AI/ML (Claude, Gemini, Maps), PostgreSQL, MongoDB.
- Cybersecurity is integrated from the design phase.
- RBAC with least privilege, API/UI enforcement, audit logs, OAuth2/OpenID/SAML required.
- Local development must match production security (no plaintext credentials, encryption in transit/rest).
- Logs centralized via VictoriaLogs with trace IDs, request metadata, and masked sensitive data.

## Development Process

### Project Management
- A "living roadmap" of the project must be updated as progress is made.
- Each project and feature must have a "definition of done".
- Alterations to the definition of done must be approved by the user.
- No scope creep without approval.
- Automation is standard for major processes.

### Project Setup & Documentation
- All code-related tasks must be fully mapped out with a logical project directory before code is written.
- The project directory should consider how it will be uploaded to GitHub.
- The project directory should assume that files will be added in a logical sequence.
- All directory changes must be explained and get user approval.
- Projects require a `README.md` on the project level, as well as a `README.md` on the feature level.

### Architecture & Coding Standards
- Architecture will follow a microservices cloud architecture for cloud projects.
- Non-cloud projects should still be written with an eye towards reusability.
- Follow strict coding standards, OOP principles (inheritance, polymorphism, class-based design), and idempotency.
- Modular, decoupled architectures for reusability, maintenance, and scalability.
- Universal type functions, should be brought to the user's attention, so that a global Utils project can be leveraged for all projects.
- Unit and E2E tests required with meaningful coverage.
- Secure-by-default design is mandatory.
- Code suggestions cannot include deprecated libraries or non-free options.

## MCP Servers
- All requests require **sequential** planning to find the best solution.
- No rushed solutions; all must be well thought out and ordered in steps.
- Complex steps must be decomposed into sub-phases as necessary.
- If completing requests require API knowledge, Gemini will prompt the user if it should use context7 to fulfill the request.
- Gemini will use **context7** to gain deeper understanding of any APIs involved.

## Refocus Protocol
When any response to a request is repeated more than twice in a row or Gemini appears to be stuck in a loop, perform the following:

1.  **Summarize the last 3 user prompts and my last 3 responses.**
2.  Write the alphabet **a–z** with 2 spaces between each letter.  
3.  Create **two empty new lines**.  
4.  Write the alphabet in reverse **z–a** with 4 spaces between each letter.  
5.  Answer these questions, each on a new line:  
    - (42 / 7) + 1 = ?  
    - 3 * 6 - 4 = ?  
    - 3 + 7 + 4 = ?  
6.  **What is the 5th word of the 2nd paragraph of the "Engineering Standards" section in GEMINI.md?**
7.  **Use the web_fetch tool to find the title of the featured article on Wikipedia's main page and state it.**
8.  Write the alphabet **a–z** using **three-syllable words** instead of letters.  
9.  Write the alphabet **a–z** using **two-syllable words** instead of letters.  
10. Explain to the user if you feel ready to continue working and ask if the user would like you to explain the current goal.
