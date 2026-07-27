---
title: Anva — Product Requirements and Implementation Plan
version: 3.0
status: Draft for founder review
product_name: Anva
supersedes: version 2.0 of this document
initial_design_partner: IIT Madras
primary_owner: Rishav Thakker
last_updated: 2026-07-28
---

# Anva

## Product Requirements, Architecture, and Implementation Roadmap

This document is the proposed canonical v3 product specification for Anva.

It replaces the v1 strategy of building and operating a complete coding-agent
control plane. The strongest parts of v1 remain: organizational knowledge,
provenance, requirements, policy, evidence, independent verification, audit
history, and post-change learning.

The major change is the product boundary:

> Anva does not operate the developer's coding agent. Anva supplies trusted
> organizational context to the coding agents developers already use, and
> independently evaluates the resulting pull request at the repository boundary.

## Why Anva?

Anva is inspired by the Sanskrit word *anvaya*—connection, continuity, and the
relationship between things.

Every organization is held together by connections: between its goals and
products, decisions and systems, requirements and code. Anva makes those
connections available to both people and AI, so every change begins with the
right context and remains aligned with its original intent.

Anva is the connective intelligence behind how your organization builds.

## Document map

| Read for | Sections |
|---|---|
| Product decision | 0–5 |
| Product architecture and data model | 6–9 |
| Developer experience | 10 |
| Pull-request assurance | 11 |
| Management experience | 12–14 |
| Policy, evidence, integrations, and security | 15–20 |
| Technical implementation | 21–24 |
| Metrics, rollout, and milestones | 25–27 |
| Detailed backlog and build controls | 28–32 |
| Risks and founder decisions | 33–35 |
| Immediate execution | 36–38 |

---

# 0. Founder Review Guide

This draft should be reviewed in the following order:

1. Product thesis and boundaries.
2. Initial customer and product wedge.
3. Anva domain model.
4. Developer-skill experience.
5. Pull-request assurance behavior.
6. Organizational Canvas.
7. Milestone roadmap.
8. Open product decisions.

The most important founder decisions requested by this document are:

- Confirm that engineering is the first organizational domain.
- Confirm that GitHub is the first system of action.
- Confirm that the first external knowledge connector may be selected with IITM
  rather than predetermined.
- Confirm that the initial server-side product ends at pull-request readiness
  and does not own deployment.
- Confirm that skills guide developers while server-side checks enforce policy.
- Confirm that the Organizational Canvas is a semantic view over Anva data,
  not a general-purpose whiteboard.
- Confirm that "production-ready from the first PR" remains a north star rather
  than a literal guarantee in initial customer contracts.

---

# 1. Executive Summary

## 1.1 Product thesis

Build a permission-aware, continuously updated model of an organization that
connects its goals, teams, products, systems, decisions, policies, work, risks,
and evidence.

Humans and agents use this model to understand the organization and make better
changes. Every accepted change produces new evidence and proposed knowledge
updates, allowing Anva to improve over time.

The initial application is engineering:

> Give every coding agent the context required to build for the organization,
> then independently verify every pull request against the organization's
> requirements, systems, policies, and evidence.

## 1.2 Initial product

The first product has four tightly connected parts:

1. **Anva Core**
   - Ingests selected organizational sources.
   - Represents entities, assertions, relationships, decisions, and policies.
   - Preserves provenance, permissions, confidence, and history.
   - Produces bounded context packets for people and agents.

2. **Developer Skills**
   - Install into Codex and Claude Code.
   - Retrieve live context from Anva through an authenticated MCP/API surface.
   - Guide requirement preparation, implementation planning, development, and
     local preflight review.
   - Propose corrections and new knowledge without silently changing Anva.

3. **PR Assurance**
   - Runs independently when a pull request is opened or updated.
   - Reads the diff, requirements, policies, Anva context, and existing CI
     results.
   - Identifies blocking gaps, advisory concerns, and areas requiring human
     attention.
   - Maps acceptance criteria to evidence.
   - Publishes a concise GitHub Check and assurance report.

4. **Organizational Canvas**
   - Gives leaders and technical owners a visual, interactive view of the
     organization.
   - Connects strategy to initiatives, teams, systems, repositories, decisions,
     risks, and active changes.
   - Provides saved semantic views, filters, drill-down, provenance, and
     time-aware exploration.

## 1.3 Product loop

```text
GitHub + organizational sources
              ↓
        Anva ingests facts
              ↓
   Humans review important claims
              ↓
Codex / Claude skill requests task context
              ↓
 Developer and coding agent prepare and implement
              ↓
       Pull request is opened
              ↓
 Anva independently evaluates the PR
              ↓
 Human reviews evidence and merges
              ↓
 Anva proposes knowledge updates
              ↓
       Accepted updates improve Anva
```

## 1.4 North star

> The first pull request should be aligned with the organization, ready for
> serious human review, and backed by credible production-grade evidence.

This is deliberately more precise than promising that every first pull request
is unconditionally safe to deploy.

## 1.5 Recommended category

Primary category:

> Organizational Intelligence and Engineering Assurance

Alternative concise description:

> The organizational context layer for humans and coding agents.

Avoid initially positioning Anva as:

- another coding agent;
- a CI replacement;
- a deployment platform;
- a general enterprise search product;
- a project-management replacement;
- an employee-monitoring system;
- an autonomous engineering manager.

## 1.6 Why v3 is narrower

Version 1 owned:

- coding-agent execution;
- disposable implementation sandboxes;
- provider routing;
- resumable agent sessions;
- branch orchestration;
- pull-request creation;
- independent verification;
- organizational knowledge.

Version 3 owns:

- organizational knowledge and context;
- reusable developer workflows;
- independent pull-request assurance;
- policy and evidence;
- a visual organizational interface.

The developer retains control of the coding environment and coding agent.
Existing CI systems retain control of builds and tests. GitHub retains control
of source collaboration and merge protection.

## 1.7 Strategic advantage

Skills and generic code review can be copied. Anva's defensible value is the
cumulative organizational model:

- trusted and corrected assertions;
- relationships between strategy, decisions, systems, and code;
- organization-specific policies;
- history of requirements and outcomes;
- evidence from real changes;
- knowledge of ownership and dependencies;
- a feedback loop that becomes more valuable with use.

---

# 2. Product Definitions and Boundaries

## 2.1 Anva

Anva is the permission-aware organizational context and memory layer.

Anva contains structured and unstructured information, but it must not claim
that all ingested information is equally trustworthy.

Anva distinguishes:

- authoritative source records;
- source-backed assertions;
- user-provided facts;
- model-inferred assertions;
- conflicting assertions;
- stale assertions;
- unreviewed proposals;
- approved decisions;
- measured evidence.

## 2.2 Source of record

An external system remains authoritative for facts it owns.

Examples:

- GitHub owns repository, commit, pull-request, and check state.
- A selected project-management system owns its issue status.
- A document system owns the current source document.
- An identity system owns membership where integrated.

Anva stores normalized representations, relationships, search indexes, and
derived assertions. It must link back to the authoritative source.

Anva becomes authoritative only for records intentionally created and governed
inside Anva, such as:

- knowledge-review decisions;
- organization-defined policies;
- manually curated relationships;
- saved Canvas views;
- Anva-native approval records;
- correction history.

## 2.3 Knowledge assertion

A knowledge assertion is a claim about an entity or relationship.

Examples:

- "Service A is owned by Team B."
- "Initiative C supports Objective D."
- "Repository E implements Product F."
- "Changes to this API require Security review."

Every assertion must identify:

- source;
- source location;
- extraction method;
- confidence;
- whether it is inferred;
- review status;
- valid time;
- observed time;
- access boundary.

## 2.4 Context packet

A context packet is a bounded, versioned selection of Anva information prepared
for a specific actor, task, repository, and phase.

It is not a dump of the entire organization.

The packet includes:

- the selection reason for every item;
- source links;
- access decision;
- freshness;
- token or size budget;
- version identifier;
- generation time.

## 2.5 Developer skill

A developer skill is a reusable workflow package used by an existing coding
agent.

The skill provides:

- when to retrieve Anva context;
- how to separate facts from assumptions;
- how to form requirements and acceptance criteria;
- how to check scope and policy;
- how to report decisions, deviations, and evidence.

A skill is not:

- the organization knowledge store;
- a secure enforcement boundary;
- proof that its instructions were followed;
- a replacement for server-side assurance.

## 2.6 Anva MCP/API

The Anva MCP/API is the authenticated live interface through which supported
agents retrieve context and submit proposals.

Read operations return only information the user and repository are authorized
to access.

Write operations create proposals or task records. They do not silently mutate
approved organizational knowledge.

## 2.7 PR Assurance Agent

The PR Assurance Agent is a server-side, event-driven evaluator.

It:

- does not implement code;
- does not operate the developer's local agent;
- does not replace deterministic CI;
- does not merge;
- does not deploy.

It evaluates the pull request using Anva context, policies, the diff, source
metadata, and available deterministic evidence.

## 2.8 CI/CD boundary

The initial product should be described externally as pull-request assurance,
not as a CI/CD platform.

The proposed "CI/CD agents" should become a staged assurance family:

1. **PR Assurance Agent** at the CI boundary — MVP.
2. **Deployment Readiness Agent** at the CD boundary — later.
3. **Post-deployment Verification Agent** — later.

Anva integrates with CI by:

- reading GitHub Check and workflow status;
- optionally accepting structured evidence from a Anva-owned GitHub Action;
- evaluating whether required checks and evidence exist;
- reporting readiness.

Anva does not initially:

- build arbitrary customer code on Anva infrastructure;
- replace a customer's workflow engine;
- host deployment credentials;
- deploy to production;
- manage rollbacks.

Deployment readiness and post-deployment verification are later expansion areas.

## 2.9 Organizational Canvas

The Canvas is a visual projection of Anva's semantic model.

Canvas position, grouping, annotations, and view settings are presentation data.
They must not be confused with the canonical entities and relationships.

The Canvas is not initially:

- a free-form design tool;
- a Figma competitor;
- a diagram file disconnected from live data;
- an unrestricted view of sensitive organizational information.

## 2.10 "Production-ready"

For the initial product, a pull request is ready for human review when:

- the intended problem and requirements are explicit;
- required deterministic checks pass;
- relevant organization policies are satisfied;
- acceptance criteria map to credible evidence or explicit gaps;
- blocking findings are resolved;
- advisory findings and limitations are visible;
- the change is appropriately scoped;
- required reviewers can identify what deserves attention.

Anva must never imply that passing assurance guarantees:

- absence of all defects;
- safe production deployment in every environment;
- sufficient infrastructure capacity;
- successful rollout;
- compliance beyond evaluated controls.

---

# 3. Binding Product Principles

## 3.1 Anva first

Every feature must either:

- improve the organizational model;
- improve retrieval of trusted context;
- improve the quality of a decision or change;
- improve the feedback loop into Anva.

Do not add agent features merely because agent platforms support them.

## 3.2 Sources before summaries

Important answers, diagrams, findings, and recommendations must link to source
records or identify themselves as inference.

## 3.3 Guidance locally, enforcement independently

Developer skills help produce the change.

Server-side PR assurance independently evaluates the result.

An agent must not be the only evaluator of its own output.

## 3.4 Preserve existing tools

Developers keep:

- their coding agent;
- their IDE or terminal;
- their repository workflow;
- their CI provider;
- their human review process.

Anva should fit into these tools rather than require a new development
environment.

## 3.5 Model independence without speculative infrastructure

Core Anva records and assurance schemas must not depend on a model vendor.

The initial reasoning implementation may use one selected provider behind a
small structured-evaluation interface.

Do not recreate a general agent-provider runtime.

## 3.6 Human authority at consequential boundaries

The initial product must not:

- merge pull requests;
- deploy;
- auto-approve architectural changes;
- silently change approved policies;
- silently overwrite reviewed relationships.

## 3.7 Temporal truth

Anva must be able to answer:

- what is believed now;
- what was believed at a prior time;
- when a claim was last verified;
- what source caused it to change.

## 3.8 Permission-aware by construction

Retrieval, Canvas views, assurance context, and source excerpts must respect the
actor's authorization.

Senior organizational role alone must not grant access to every source.

## 3.9 No employee surveillance

Anva may show:

- ownership;
- work state;
- system risk;
- approval responsibility;
- unresolved organizational dependency.

Anva must not initially calculate:

- individual productivity scores;
- developer rankings;
- "AI utilization" rankings;
- lines-of-code performance;
- inferred employee sentiment;
- hidden performance assessments.

## 3.10 Conservative claims

Anva must separate:

- deterministic failure;
- policy violation;
- source-backed fact;
- model-identified concern;
- suggestion;
- unknown.

## 3.11 Minimum justified complexity

Use PostgreSQL and explicit domain models initially.

Do not add:

- a graph database;
- a general workflow engine;
- a data lake;
- a vector database separate from PostgreSQL;
- a customer-code sandbox platform;

until measured requirements justify them.

## 3.12 Product-first dogfooding

Every release should be used in the IIT Madras engineering workflow.

Manual founder interventions must be categorized, measured, and converted into
product improvements.

---

# 4. Initial Scope

## 4.1 Initial customer boundary

The first Anva models an engineering organization and its immediate product
context.

It does not attempt to model the complete finance, HR, legal, sales, and
operations organization in the first release.

## 4.2 In scope for MVP

### Anva Core

- Organization and membership.
- Product, goal, initiative, team, and ownership entities.
- Repository, service, component, API, data asset, and environment entities.
- Decision, policy, risk, incident, requirement, and acceptance-criterion
  entities.
- Source ingestion with provenance.
- Assertions, relationships, confidence, review state, and validity.
- Search and bounded context retrieval.
- Correction and knowledge-review workflow.
- Time-aware revision history.

### Integrations

- GitHub App installation.
- Selected repository onboarding.
- Repository metadata and documentation ingestion.
- Issue, pull request, review, check, and merge event handling.
- One external organizational-document source chosen with the design partner.
- Authenticated remote Anva MCP/API.

### Developer experience

- Codex distribution package containing Anva skills and MCP configuration.
- Claude Code distribution package containing equivalent Anva skills and MCP
  configuration.
- Prepare workflow.
- Build-with-context workflow.
- Local preflight workflow.
- Knowledge-correction workflow.
- Installation diagnostics.
- Version and capability compatibility checks.

### Pull-request assurance

- Pull-request ingestion and diff analysis.
- Requirement and task linking.
- Existing CI result collection.
- Optional structured evidence upload from customer CI.
- Policy evaluation.
- Independent model review.
- Acceptance-criterion evidence mapping.
- Findings and readiness decision.
- GitHub Check result and pull-request report.
- Re-evaluation after relevant changes.
- Post-merge knowledge-update proposals.

### Web product

- Organization setup.
- Source and repository onboarding.
- Anva Explorer.
- Organizational Canvas.
- Knowledge review inbox.
- Repository profile.
- Policy management.
- Pull-request assurance detail.
- Source health and freshness.
- Audit history.
- Skill installation and diagnostics.

## 4.3 Explicitly out of scope for MVP

- Operating Codex, Claude Code, or another coding agent.
- Agent session hosting.
- Coding-agent provider routing.
- Automatic code implementation.
- Automatic branch or pull-request creation.
- Resumable remote coding sessions.
- Disposable implementation VMs.
- General customer-code execution on Anva infrastructure.
- CI pipeline replacement.
- Production deployment.
- Autonomous merge.
- Rollback automation.
- Full bug-reproduction infrastructure.
- Browser automation hosted by Anva.
- GitLab and Bitbucket.
- Multiple external document connectors.
- Company-wide HR or finance modeling.
- General-purpose enterprise search.
- General-purpose diagramming.
- Individual employee scoring.
- Dedicated graph database.
- Customer-specific model training.
- Multi-repository autonomous implementation.

## 4.4 Later expansion areas

After the engineering loop is trusted:

- additional coding-agent hosts;
- GitLab support;
- issue-tracker and incident-management connectors;
- deployment-readiness assurance;
- post-deployment verification;
- release-level assurance;
- cross-repository coordinated change analysis;
- customer-facing requirement traceability;
- product and operational planning workflows;
- scenario planning on the Canvas;
- private-network and customer-hosted Anva workers;
- broader organizational domains.

## 4.5 Scope test

Before accepting a new feature, answer:

1. Does it improve trusted organizational context?
2. Does it improve the first-PR outcome?
3. Does it strengthen the feedback loop into Anva?
4. Can it be achieved without owning the coding harness or CI system?
5. Is it required by a current design-partner workflow?

If fewer than two answers are yes, defer the feature.

---

# 5. Personas and Jobs

## 5.1 Developer using a coding agent

Needs:

- relevant organizational context without searching many systems;
- accurate repository commands and conventions;
- clear requirements and acceptance criteria;
- awareness of dependencies, policies, and prior decisions;
- a fast preflight before opening a pull request;
- actionable assurance findings;
- a low-friction way to correct Anva.

Primary job:

> Help me and my coding agent make the right change without rediscovering how
> this organization works.

## 5.2 Technical lead

Needs:

- architectural consistency;
- dependency and ownership visibility;
- review focus;
- policy enforcement;
- source-backed findings;
- knowledge corrections that remain reviewed and auditable.

Primary job:

> Show me whether this change fits our systems and where my judgment is most
> needed.

## 5.3 Engineering leader

Needs:

- connection between objectives, initiatives, systems, and current work;
- visibility into organizational dependencies and risks;
- confidence that AI-assisted development respects organizational standards;
- reduced requirement-related rework;
- consistent first-pass pull-request quality.

Primary job:

> Let me understand how the engineering organization is operating and intervene
> at the right level.

## 5.4 Product owner

Needs:

- explicit requirements and non-requirements;
- linkage from product intent to implementation;
- acceptance evidence;
- visibility into scope changes;
- status without manually reconstructing it from multiple tools.

Primary job:

> Preserve product intent from the original need through the implemented change.

## 5.5 Security or platform owner

Needs:

- enforceable policy;
- required approvals;
- sensitive-system identification;
- traceable overrides;
- no hidden credentials or ungoverned execution;
- clear separation between deterministic failures and model concerns.

Primary job:

> Ensure that agent-assisted changes obey our controls without replacing our
> existing security and CI systems.

## 5.6 Knowledge steward

This may initially be a technical lead or product owner rather than a dedicated
role.

Needs:

- a queue of uncertain, conflicting, stale, and high-impact claims;
- efficient bulk review;
- source comparison;
- revision history;
- ownership of specific knowledge domains.

Primary job:

> Keep the Anva trustworthy without manually curating every extracted fact.

---

# 6. Product Architecture

## 6.1 Logical architecture

```text
                         ┌───────────────────────────┐
                         │   Organizational Canvas   │
                         │ Explorer · Query · Review │
                         └─────────────┬─────────────┘
                                       │
┌──────────────┐       ┌───────────────▼────────────────┐
│ GitHub       │──────▶│             Anva Core          │
│ Repositories │       │ entities · assertions · sources │
│ Issues / PRs │◀──────│ relationships · history · ACLs  │
└──────────────┘       └───────────────┬────────────────┘
                                       │
┌──────────────┐       ┌───────────────▼────────────────┐
│ Document     │──────▶│      Context and Policy API     │
│ Source       │       │ search · packets · explanations │
└──────────────┘       └───────┬───────────────┬────────┘
                                │               │
                    ┌───────────▼────┐   ┌──────▼──────────┐
                    │ Codex / Claude │   │ PR Assurance     │
                    │ Anva Skills   │   │ Agent + Evidence │
                    └────────────────┘   └─────────────────┘
```

## 6.2 Planes

### Knowledge plane

Owns:

- sources;
- entities;
- assertions;
- relationships;
- revisions;
- review;
- search;
- retrieval;
- freshness.

### Interaction plane

Owns:

- Anva web application;
- Canvas;
- authenticated API;
- MCP tools;
- developer skills;
- correction proposals.

### Assurance plane

Owns:

- pull-request state;
- policy evaluation;
- deterministic evidence ingestion;
- independent review;
- findings;
- readiness;
- GitHub reporting;
- post-merge proposals.

## 6.3 Trust boundaries

Treat the following as untrusted:

- repository source code;
- issues and comments;
- pull-request descriptions;
- documents;
- test logs;
- model output;
- skill-submitted summaries;
- external webhook payloads before verification.

Server-side authorization, policy, and state transitions must not depend on
instructions found in untrusted content.

## 6.4 Core product boundary

Anva stores organizational context and evaluates changes.

It does not require visibility into the developer's entire agent conversation.
The skill may submit a structured work summary with explicit user awareness, but
raw local prompts and transcripts are not collected by default.

## 6.5 Model use

Models may assist with:

- entity and relationship extraction;
- source classification;
- context ranking;
- contradiction detection;
- requirement normalization;
- pull-request review;
- knowledge-update proposals;
- natural-language query.

Models must not directly:

- grant access;
- approve plans on behalf of humans;
- mark deterministic checks passed;
- overwrite reviewed knowledge;
- merge;
- deploy.

---

# 7. Core Domain Model

## 7.1 Identity and tenancy

- `Organization`
- `User`
- `Membership`
- `Role`
- `Team`
- `TeamMembership`
- `ServiceIdentity`
- `AccessGrant`
- `ExternalIdentity`

Initial roles:

```text
ORG_ADMIN
KNOWLEDGE_ADMIN
TECHNICAL_OWNER
PRODUCT_OWNER
DEVELOPER
REVIEWER
SECURITY_REVIEWER
VIEWER
```

## 7.2 Source model

- `SourceConnection`
- `SourceContainer`
- `SourceDocument`
- `SourceRevision`
- `SourceLocation`
- `SyncRun`
- `SyncCursor`
- `IngestionFailure`
- `AccessSnapshot`

Every source revision records:

```text
organization_id
connection_id
external_id
canonical_url
content_hash
source_modified_at
observed_at
access_snapshot_id
parser_version
raw_artifact_reference
```

Raw source content may be stored according to organization retention policy.
Where raw storage is not allowed, Anva must store an authorized retrieval
reference and derived records with sufficient provenance.

## 7.3 Organizational entities

Initial explicit entity types:

- `Goal`
- `Metric`
- `Initiative`
- `Product`
- `Team`
- `Owner`
- `Repository`
- `Service`
- `Component`
- `API`
- `DataAsset`
- `Environment`
- `CustomerCommitment`
- `ArchitecturalDecision`
- `Policy`
- `Risk`
- `Incident`
- `Requirement`
- `AcceptanceCriterion`
- `Task`
- `PullRequest`
- `Release`

Do not create a new database table for every future noun.

Recommended pattern:

- common `KnowledgeEntity` identity and lifecycle;
- explicit typed detail tables for high-value types with unique behavior;
- typed JSON attributes only for low-risk, evolving metadata;
- database constraints for critical invariants.

## 7.4 Knowledge assertions

- `KnowledgeAssertion`
- `AssertionRevision`
- `AssertionSource`
- `AssertionReview`
- `AssertionConflict`
- `CorrectionProposal`

Suggested assertion shape:

```json
{
  "subject_entity_id": "ent_service_checkout",
  "predicate": "owned_by",
  "object_entity_id": "ent_team_payments",
  "literal_value": null,
  "confidence": 0.94,
  "is_inferred": false,
  "review_status": "HUMAN_CONFIRMED",
  "valid_from": "2026-06-01T00:00:00Z",
  "valid_until": null,
  "observed_at": "2026-07-28T00:00:00Z",
  "source_ids": ["src_codeowners_17"],
  "access_scope_id": "acl_engineering"
}
```

## 7.5 Relationship vocabulary

Initial relationship types:

```text
GOAL_MEASURED_BY_METRIC
INITIATIVE_SUPPORTS_GOAL
INITIATIVE_OWNED_BY_TEAM
INITIATIVE_AFFECTS_PRODUCT
PRODUCT_IMPLEMENTED_BY_REPOSITORY
COMPONENT_BELONGS_TO_PRODUCT
REPOSITORY_OWNED_BY_TEAM
REPOSITORY_CONTAINS_COMPONENT
SERVICE_IMPLEMENTED_BY_REPOSITORY
SERVICE_DEPENDS_ON_SERVICE
API_PROVIDED_BY_SERVICE
API_CONSUMED_BY_COMPONENT
DATA_ASSET_USED_BY_SERVICE
DECISION_APPLIES_TO_ENTITY
POLICY_APPLIES_TO_ENTITY
RISK_AFFECTS_ENTITY
INCIDENT_AFFECTED_ENTITY
REQUIREMENT_SUPPORTS_INITIATIVE
REQUIREMENT_IMPLEMENTED_BY_PULL_REQUEST
ACCEPTANCE_CRITERION_VERIFIED_BY_EVIDENCE
TASK_CHANGES_ENTITY
PULL_REQUEST_CHANGES_ENTITY
ENTITY_OWNED_BY_OWNER
ENTITY_REVIEWED_BY_TEAM
```

Relationship types must define:

- allowed subject types;
- allowed object types;
- whether direction is meaningful;
- whether multiple active relationships are permitted;
- whether human confirmation is required;
- default freshness window;
- visibility rules.

## 7.6 Entity resolution

Anva must avoid creating duplicate entities for the same system.

Resolution inputs may include:

- stable external identifiers;
- repository URLs;
- normalized names;
- aliases;
- ownership;
- source links;
- human-confirmed mappings.

Resolution outcomes:

```text
MATCHED
CREATED
AMBIGUOUS
CONFLICT
IGNORED
```

Ambiguous high-impact entities must enter review rather than being merged
automatically.

## 7.7 Repository profile

- `RepositoryProfile`
- `RepositoryCommand`
- `RepositoryRuntime`
- `RepositoryService`
- `RepositoryEnvironment`
- `RepositoryPolicyBinding`
- `RepositoryPathRule`
- `RepositorySecretReference`
- `RepositoryProfileRevision`

Example:

```yaml
repository:
  purpose: Online examination platform
  owners:
    - platform-team
  products:
    - exam-platform

runtime:
  language: python
  version: "3.12"
  framework: django
  database: postgres

commands:
  setup: make setup
  lint: make lint
  typecheck: make typecheck
  unit_test: make test-unit
  integration_test: make test-integration

ci:
  provider: github-actions
  required_checks:
    - lint
    - typecheck
    - unit-tests

assurance:
  browser_evidence_required_for:
    - "apps/web/**"
  migration_policy:
    - backward-compatible-migrations
  sensitive_paths:
    - "authentication/**"
    - "payments/**"
```

## 7.8 Work and requirements

- `WorkItem`
- `WorkItemRevision`
- `Requirement`
- `NonRequirement`
- `Assumption`
- `AcceptanceCriterion`
- `Decision`
- `Approval`
- `ContextPacket`
- `ContextPacketItem`
- `WorkSummary`

Every requirement records:

- origin;
- normalized text;
- source references;
- owner;
- status;
- version;
- related entities;
- acceptance criteria;
- approval where required.

## 7.9 Policy

- `Policy`
- `PolicyVersion`
- `PolicyBinding`
- `PolicyEvaluation`
- `PolicyRequirement`
- `PolicyOverride`

Policies may require:

- deterministic checks;
- evidence types;
- specific reviewers;
- approval;
- report sections;
- blocking or advisory findings.

## 7.10 Pull-request assurance

- `PullRequestRecord`
- `PullRequestRevision`
- `AssuranceRun`
- `AssuranceCheck`
- `ModelEvaluation`
- `Evidence`
- `CriterionEvidence`
- `Finding`
- `FindingOccurrence`
- `ReadinessDecision`
- `AssuranceReport`
- `KnowledgeUpdateProposal`

## 7.11 Canvas

- `CanvasView`
- `CanvasViewRevision`
- `CanvasNodePlacement`
- `CanvasGroup`
- `CanvasAnnotation`
- `CanvasFilter`
- `CanvasLayer`
- `CanvasShare`

Canvas records refer to canonical `KnowledgeEntity` identifiers. Deleting a
Canvas view must not delete the entities it displayed.

## 7.12 Audit

- `AuditEvent`
- `ExternalEvent`
- `OutboundNotification`
- `RenderedExternalContent`

Every mutating action records:

```text
organization_id
actor_type
actor_id
action
target_type
target_id
authorization_path
request_id
source_ip_hash_or_equivalent
created_at
metadata
```

Audit metadata must not contain secret values or unrestricted source content.

---

# 8. Anva Knowledge Lifecycle

## 8.1 Source connection

1. Administrator authorizes a source.
2. Anva discovers accessible containers.
3. Administrator selects scope.
4. Anva captures the initial access boundary.
5. A sync begins.
6. Source health and coverage are visible.

## 8.2 Ingestion pipeline

```text
Discover
→ Fetch
→ Verify access
→ Parse
→ Chunk
→ Index
→ Extract candidate entities
→ Resolve entities
→ Extract candidate assertions
→ Detect conflict
→ Assign review policy
→ Publish eligible assertions
```

Every phase must be independently retryable and idempotent.

## 8.3 Extraction classes

### Mechanical

Examples:

- repository name;
- default branch;
- CODEOWNERS entry;
- package dependency;
- workflow check name;
- file path.

High-confidence mechanical facts may publish automatically.

### Interpretive

Examples:

- service purpose;
- architectural responsibility;
- initiative relationship;
- risk;
- implied ownership.

Interpretive claims must retain their inference label. High-impact interpretive
claims require human review before being treated as approved.

## 8.4 Review priority

Prioritize review using:

- impact of the entity;
- confidence;
- conflict;
- frequency of retrieval;
- use in blocking policy;
- staleness;
- number of downstream relationships;
- correction history.

The review queue should surface the smallest set of decisions that most improves
Anva reliability.

## 8.5 Conflict behavior

When sources disagree:

- retain both claims;
- identify their sources and validity intervals;
- do not silently select the most recent text as truth;
- apply source-authority rules where explicitly configured;
- request review when the conflict affects assurance or ownership.

## 8.6 Staleness

Assertions may become stale because:

- a source changed;
- a source disappeared;
- the owner changed;
- a newer decision superseded an older one;
- a merged change contradicted the current model;
- the configured freshness interval expired.

Staleness states:

```text
FRESH
AGING
STALE
CONTRADICTED
SOURCE_UNAVAILABLE
```

Stale information may be retrieved only with a visible warning and must not
silently satisfy a blocking policy.

## 8.7 Corrections

Users and skills may propose:

- corrected value;
- corrected relationship;
- entity merge;
- entity split;
- source authority change;
- stale marking;
- deletion request;
- new decision or policy.

Correction workflow:

```text
PROPOSED
→ VALIDATING
→ AWAITING_REVIEW
→ ACCEPTED | REJECTED | SUPERSEDED
```

Repeatedly corrected automated assertions should be down-ranked or require
review before republication.

## 8.8 Post-merge learning

After a pull request merges:

1. Compare the prior Anva model, requirements, final diff, and assurance
   evidence.
2. Identify possible changes to systems, APIs, ownership, dependencies,
   commands, policies, and decisions.
3. Create knowledge-update proposals.
4. Automatically accept only high-confidence mechanical changes.
5. Route architectural or uncertain changes to review.
6. preserve prior versions and source links.

## 8.9 Knowledge quality criteria

- Every active assertion has at least one source or an explicit human-author
  record.
- Every inferred assertion is visibly labeled.
- Review history is preserved.
- Access is re-evaluated when source permissions change.
- Source deletion and revocation propagate according to retention policy.
- A user can explain why a context item or relationship exists.
- A user can report incorrect information from every major view.
- Anva can reconstruct the knowledge version used by an assurance run.

---

# 9. Context and Query System

## 9.1 Context request inputs

```json
{
  "organization_id": "org_123",
  "actor_id": "user_123",
  "repository_id": "repo_123",
  "work_item_id": "work_123",
  "pull_request_id": null,
  "phase": "PREPARE",
  "query": "Add exam rescheduling support",
  "changed_paths": [],
  "budget": {
    "max_items": 80,
    "max_tokens": 24000
  }
}
```

## 9.2 Retrieval stages

1. Resolve organization, actor, repository, and task.
2. Enforce access scope before ranking.
3. Retrieve required policy and repository-profile context.
4. Retrieve direct entity relationships.
5. Retrieve relevant source excerpts.
6. Retrieve prior incidents and decisions where risk warrants.
7. Rank for phase and task.
8. remove duplicates and contradicted low-authority claims.
9. Fit the bounded packet.
10. Store the exact packet and selection explanations.

## 9.3 Phase-specific retrieval

### Prepare

Prefer:

- product intent;
- goal and initiative;
- prior related requirements;
- owners;
- relevant decisions;
- affected systems;
- policies;
- incidents.

### Build

Prefer:

- approved requirements;
- acceptance criteria;
- repository profile;
- code and architecture conventions;
- dependencies;
- required tests;
- sensitive paths;
- plan decisions.

### Preflight

Prefer:

- approved scope;
- acceptance criteria;
- changed paths;
- required checks;
- documentation requirements;
- migration and security policies;
- known risk areas.

### Assurance

Prefer:

- immutable approved requirement version;
- diff and base/head commit;
- exact policy versions;
- relevant Anva revision;
- deterministic evidence;
- related decisions and dependencies.

## 9.4 Context packet shape

```json
{
  "packet_id": "ctx_123",
  "context_version": "sha256:...",
  "generated_at": "2026-07-28T00:00:00Z",
  "phase": "BUILD",
  "actor": {
    "id": "user_123",
    "authorization_snapshot": "acl_123"
  },
  "task": {},
  "requirements": [],
  "acceptance_criteria": [],
  "repository_profile": {},
  "affected_entities": [],
  "policies": [],
  "decisions": [],
  "risks_and_incidents": [],
  "source_excerpts": [],
  "assumptions": [],
  "unresolved_conflicts": [],
  "selection_explanations": [],
  "budget": {},
  "limitations": []
}
```

## 9.5 Query experience

Users may ask natural-language questions, but Anva answers must be assembled
from permission-filtered records.

Every material answer should provide:

- concise answer;
- source links;
- confidence and freshness;
- inferred portions;
- unresolved conflicts;
- suggested next action where appropriate.

Example questions:

- Which initiatives depend on the identity service?
- Why does the payments repository require a security reviewer?
- Which goals have no active engineering work?
- What changed in the exam platform this month?
- Which pull requests affected this customer commitment?
- What information about this service is stale?

## 9.6 Query safety

- Natural-language input never expands authorization.
- Returned source excerpts must obey source ACLs.
- The answer generator cannot turn an inaccessible source title into a visible
  existence leak when organization policy forbids it.
- Tool output must be bounded.
- Retrieved untrusted instructions must be labeled as content, not system
  instructions.

## 9.7 Context quality metrics

- required-policy recall;
- owner and system resolution accuracy;
- source-link completeness;
- human-rated relevance;
- stale-item rate;
- incorrect-assertion report rate;
- packet size;
- retrieval latency;
- percent of packet items actually used in assurance output.

---

# 10. Developer Skills and Live Anva Access

## 10.1 Architecture decision

Ship a small family of portable Anva skills plus authenticated Anva MCP tools.

The skill defines the workflow. MCP supplies live, permission-filtered
organizational context.

Do not embed customer knowledge inside distributable skill packages.

## 10.2 Supported initial hosts

### Codex

The initial Codex distribution should be a Anva plugin that packages:

- Anva skills;
- Anva MCP server configuration or registered connection;
- installation metadata;
- optional non-enforcing lifecycle helpers only after explicit trust.

Codex also supports repository-local skills. The canonical Anva skill source
must remain host-neutral and generate or package the provider-specific layout.

### Claude Code

The initial Claude Code distribution should include:

- project or user skills;
- Anva remote MCP configuration;
- an installer and diagnostic command;
- optional plugin packaging if it improves organization-wide distribution.

## 10.3 Portable core

Maintain one conceptual workflow specification and thin host adapters.

```text
packages/anva-skills/
├── workflows/
│   ├── prepare/
│   ├── build-with-anva/
│   ├── preflight/
│   └── learn/
├── shared/
│   ├── evidence-rules.md
│   ├── provenance-rules.md
│   └── output-schemas/
├── hosts/
│   ├── codex/
│   └── claude-code/
└── evals/
```

Do not assume byte-identical skill files will behave identically across hosts.
Host packaging, invocation, tool names, permissions, and evaluation must be
tested separately.

## 10.4 Skill suite

### `anva-prepare`

Purpose:

- start from an issue or task;
- retrieve product and system context;
- identify ambiguity;
- separate confirmed requirements from assumptions;
- produce acceptance criteria and an implementation/verification plan;
- record the approved plan reference where the organization uses approval.

Required output:

```markdown
## Problem
## Confirmed requirements
## Out of scope
## Assumptions
## Acceptance criteria
## Affected systems and owners
## Relevant decisions and policies
## Implementation plan
## Verification plan
## Unresolved questions
## Anva sources
```

### `anva-build`

Purpose:

- retrieve the approved context packet before material implementation;
- keep the coding agent within scope;
- surface repository commands and policies;
- record discovered deviations and new ambiguity;
- prevent source content from being treated as privileged instructions.

The skill should pause and ask the user when:

- a requirement materially changes;
- a blocking policy cannot be satisfied;
- the change affects an unapproved system;
- Anva contains a material unresolved conflict;
- implementation requires a secret or environment not available to the user.

### `anva-preflight`

Purpose:

- inspect the local diff before pull-request creation;
- compare it with requirements and acceptance criteria;
- run repository-defined checks selected by changed paths and policy;
- identify missing tests, documentation, migrations, or evidence;
- produce a structured local readiness summary.

Preflight is advisory. It is not the authoritative server-side assurance result.

### `anva-learn`

Purpose:

- propose a correction when Anva is wrong;
- propose a new relationship or decision discovered during work;
- submit a structured implementation summary;
- explain what changed and why;
- avoid directly approving its own proposal.

## 10.5 MCP tool surface

Initial read tools:

```text
anva.resolve_repository
anva.resolve_work_item
anva.get_context_packet
anva.search
anva.get_entity
anva.get_relationships
anva.get_repository_profile
anva.get_policy_bundle
anva.get_requirements
anva.explain_assertion
anva.get_source_excerpt
```

Initial proposal tools:

```text
anva.propose_correction
anva.propose_relationship
anva.propose_decision
anva.submit_work_summary
anva.submit_preflight_summary
```

Proposal tools must:

- identify the authenticated actor;
- show the proposed content;
- record source references;
- require explicit tool approval where the host supports approval;
- return a proposal identifier and review state;
- never return success as if approved knowledge was already changed.

## 10.6 Authentication

Preferred initial flow:

- remote HTTPS MCP;
- organization sign-in through OAuth;
- short-lived access tokens;
- repository and organization scopes;
- revocation from Anva;
- no long-lived customer API key embedded in a repository.

For headless or enterprise-managed environments, support a separately governed
service identity with explicit scope.

## 10.7 Skill context minimization

The skill should request context by task and phase.

It must not:

- request all organization knowledge;
- request unrelated source documents;
- cache unrestricted source content in the repository;
- write tokens into generated files;
- submit raw conversation transcripts by default.

## 10.8 Skill versioning

Every skill invocation should make the following discoverable:

- Anva skill version;
- host and host version;
- supported MCP capability version;
- repository;
- context packet version;
- workflow phase.

Anva should remain backward compatible for at least one previous stable skill
version during the private beta.

## 10.9 Skill evaluation

Maintain an evaluation suite with:

- representative repositories;
- clear and ambiguous issues;
- stale and conflicting Anva assertions;
- policy-triggering diffs;
- prompt-injection content;
- missing-context scenarios;
- over-broad implementation temptation;
- unauthorized-source attempts.

Evaluate separately on Codex and Claude Code.

Required measures:

- correct skill triggering;
- correct tool selection;
- context relevance;
- requirement completeness;
- scope adherence;
- unsupported claim rate;
- sensitive-data leakage;
- preflight finding precision and recall;
- proposal quality.

## 10.10 Skill acceptance criteria

- A developer can install Anva without changing coding agents.
- Both supported hosts can authenticate to the same Anva organization.
- The same task produces semantically equivalent context across hosts.
- Skill instructions never contain organization secrets.
- Every material context claim links to Anva provenance.
- The skill behaves safely when Anva is unreachable.
- The skill does not claim server-side assurance passed.
- Write operations create reviewable proposals.
- Skill updates are versioned and testable.
- Installation can be diagnosed without exposing tokens.

---

# 11. Pull-Request Assurance

## 11.1 Goal

Independently determine whether a pull request is aligned with its intended
requirements, relevant organizational knowledge, repository rules, and
organization policy, and whether it is ready for focused human review.

## 11.2 Inputs

- GitHub organization, repository, and pull-request identity.
- Base and head commit.
- Pull-request title, description, labels, and linked work item.
- Diff and changed paths.
- Approved requirements and acceptance criteria where available.
- Repository profile.
- Relevant Anva entities, decisions, dependencies, risks, and incidents.
- Exact policy versions.
- Existing GitHub Checks and workflow results.
- Structured evidence uploaded from CI where configured.
- Prior assurance runs and finding resolution.

## 11.3 Evaluation layers

### Layer 1: Deterministic repository state

Examples:

- mergeability;
- base/head identity;
- required check completion;
- test exit status;
- lint and type-check status;
- migration check status;
- dependency scan result;
- generated-file consistency;
- required approval presence;
- required file or report existence.

Anva may consume deterministic status but must not fabricate it.

### Layer 2: Deterministic Anva policy

Examples:

- sensitive path requires security reviewer;
- migration requires rollback evidence;
- browser-visible change requires browser evidence;
- public API change requires compatibility review;
- affected product requires product-owner approval;
- critical service requires two reviewers.

### Layer 3: Structured change analysis

Examples:

- likely affected components;
- requirement coverage;
- unnecessary scope;
- architecture consistency;
- dependency impact;
- missing error handling;
- missing tests;
- documentation mismatch;
- changed behavior absent from requirements.

This layer may use a model but returns schema-validated findings with cited diff
locations and Anva sources.

### Layer 4: Evidence mapping

For each acceptance criterion:

- identify relevant evidence;
- state whether the evidence is direct or indirect;
- state limitations;
- identify blocking gaps;
- avoid marking a criterion satisfied from a summary alone.

### Layer 5: Human-review focus

Produce a small, prioritized list of questions or areas requiring human
judgment.

## 11.4 Triggering

An assurance run starts when:

- a pull request is opened;
- a non-draft pull request becomes ready for review;
- the head commit changes;
- a required deterministic check completes;
- a relevant requirement or policy version changes;
- an authorized user requests re-evaluation.

Events must be debounced so a burst of check completions does not create
unbounded duplicate model runs.

## 11.5 Pull-request linkage

Preferred linking order:

1. Explicit Anva work-item identifier.
2. Supported issue-closing syntax.
3. Branch or pull-request metadata.
4. Human-confirmed suggested link.

Anva must not silently bind an ambiguous pull request to requirements.

If no work item is linked, assurance may still evaluate repository policy and
change quality, but readiness must state that requirement-level coverage could
not be established.

## 11.6 Readiness statuses

```text
NOT_EVALUATED
EVALUATING
BLOCKED
READY_WITH_WARNINGS
READY_FOR_HUMAN_REVIEW
STALE
FAILED
```

### `BLOCKED`

Use when:

- a required deterministic check failed;
- a blocking policy failed;
- a required approval is missing;
- a required acceptance criterion has no credible evidence;
- the implementation materially contradicts approved requirements;
- the current run cannot safely evaluate a critical required area.

### `READY_WITH_WARNINGS`

Use when:

- all blocking checks pass;
- required evidence is present;
- advisory concerns or explicit non-critical gaps remain;
- human review should focus on identified uncertainty.

### `READY_FOR_HUMAN_REVIEW`

Use when:

- required checks pass;
- blocking policies pass;
- acceptance criteria have credible evidence;
- no unresolved blocking findings remain;
- the analysis is current for the head commit;
- remaining limitations are minor and visible.

### `STALE`

Use when:

- the head commit changed;
- required evidence changed;
- a relevant policy or requirement version changed;
- the run's Anva context was invalidated by a material correction.

## 11.7 Finding taxonomy

Finding kind:

```text
DETERMINISTIC_FAILURE
POLICY_VIOLATION
REQUIREMENT_GAP
SCOPE_DEVIATION
ARCHITECTURE_CONCERN
SECURITY_CONCERN
RELIABILITY_CONCERN
TEST_GAP
DOCUMENTATION_GAP
DEPENDENCY_IMPACT
KNOWLEDGE_CONFLICT
EVIDENCE_GAP
SUGGESTION
```

Finding severity:

```text
BLOCKING
HIGH
MEDIUM
LOW
INFORMATIONAL
```

Finding confidence:

```text
PROVEN
HIGH_CONFIDENCE
PLAUSIBLE
SPECULATIVE
```

A model-generated concern cannot be labeled `PROVEN` without deterministic or
source-backed support.

## 11.8 Finding requirements

Every finding must include:

- concise title;
- category and severity;
- confidence class;
- explanation;
- affected file and line when applicable;
- related requirement, policy, or Anva entity;
- evidence and source references;
- suggested resolution;
- statement of uncertainty;
- stable fingerprint.

Findings without actionable location or organizational relevance should be
omitted or grouped as low-priority observations.

## 11.9 Finding lifecycle

```text
OPEN
ACKNOWLEDGED
RESOLVED_BY_CHANGE
RESOLVED_BY_EVIDENCE
DISMISSED
ACCEPTED_RISK
OBSOLETE
```

Dismissal or accepted risk requires:

- authorized actor;
- reason;
- timestamp;
- head commit;
- audit event.

A finding must reopen when a new diff invalidates the resolution.

## 11.10 Deterministic CI integration

Initial modes:

### Mode A: Observe existing GitHub Checks

Anva reads:

- check name;
- app/provider;
- status and conclusion;
- start and completion time;
- target commit;
- details URL;
- annotations where available.

This is the default and lowest-friction mode.

### Mode B: Anva Evidence Action

Provide a small GitHub Action or CLI that uploads a signed evidence manifest
after customer-owned commands run.

Example:

```yaml
- name: Upload Anva evidence
  uses: brainhq/evidence-action@v1
  with:
    manifest: .anva/evidence.json
```

Example manifest:

```json
{
  "schema_version": "1",
  "commit_sha": "abc123",
  "checks": [
    {
      "type": "TEST_RESULT",
      "name": "unit-tests",
      "command": "make test-unit",
      "exit_code": 0,
      "report_path": "reports/junit.xml"
    }
  ]
}
```

The action must not upload arbitrary workspace contents by default.

### Mode C: Managed execution

Deferred. Add only when customers demonstrate that consuming existing CI is
insufficient.

## 11.11 Model evaluation interface

Use a small, stateless structured interface rather than a coding-agent runtime.

```python
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class EvaluationRequest:
    assurance_run_id: str
    context_packet_id: str
    diff_artifact_id: str
    evaluation_kind: str
    output_schema_version: str

@dataclass(frozen=True)
class EvaluationResult:
    status: str
    findings: list[dict]
    criterion_assessments: list[dict]
    usage: dict
    provider_metadata: dict

class ReasoningEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        ...
```

Requirements:

- structured output validation;
- explicit timeout;
- retry policy;
- usage recording;
- prompt and context version recording;
- redaction;
- no shell;
- no repository credentials;
- no direct database access;
- fake evaluator for tests.

## 11.12 Large pull requests

For diffs above configured size:

- parse and classify changed files;
- prioritize sensitive and behavior-changing areas;
- analyze in bounded chunks;
- merge findings by stable fingerprint;
- state coverage limitations;
- never imply complete review when context was truncated.

Organizations may configure a policy requiring pull-request splitting above a
threshold, but line count alone should not be the only criterion.

## 11.13 Re-evaluation

Re-evaluation should:

- preserve earlier runs;
- compare findings across commits;
- mark obsolete findings;
- reuse unchanged deterministic evidence only when tied to the current commit or
  safely reusable;
- avoid re-posting duplicate inline comments;
- publish one current summary;
- retain an auditable timeline.

## 11.14 Assurance report

```markdown
# Anva assurance

## Readiness

READY_WITH_WARNINGS

Evaluated commit: `abc123`
Anva context: `ctx_123`
Policy bundle: `policy_17`

## Intended change

- Work item:
- Requirements:
- Out of scope:

## Required checks

| Check | Status | Evidence |
|---|---|---|

## Acceptance criteria

| Criterion | Status | Evidence | Limitations |
|---|---|---|---|

## Blocking findings

## Advisory findings

## Organizational impact

- Products:
- Systems:
- Teams:
- Dependencies:

## Human-review focus

## Unverified areas

## Anva sources
```

## 11.15 Report rules

- Lead with readiness and blocking gaps.
- Do not repeat the entire pull-request description.
- Do not claim tests passed without stored deterministic status.
- Separate proven failures from model concerns.
- Link to the detailed Anva view rather than posting enormous comments.
- Make the evaluated commit explicit.
- Show when a result becomes stale.

## 11.16 Assurance acceptance criteria

- A pull request can be evaluated without Anva executing customer code.
- Existing CI status is associated with the exact commit.
- Every blocking decision is explainable.
- Every policy evaluation records the exact policy version.
- Every criterion maps to evidence or an explicit gap.
- Model findings cite diff or Anva sources.
- Duplicate webhooks do not create duplicate reports.
- Re-evaluation preserves history.
- Developers can dismiss advisory findings with a reason.
- Blocking overrides require configured authority.
- The check never claims to merge or deploy safely.
- A human can identify the highest-value review areas in under two minutes.

---

# 12. Organizational Canvas

## 12.1 Goal

Give leaders, product owners, and technical owners a live, visual, explainable
model of the engineering organization and its relationship to organizational
goals.

## 12.2 Canvas principle

The Canvas is a queryable semantic view, not a manually maintained drawing.

Every canonical node should support:

- identity;
- type;
- owner;
- status;
- relationships;
- freshness;
- provenance;
- permitted actions.

## 12.3 Initial saved view types

### Strategy view

```text
Goal
→ Metric
→ Initiative
→ Product
→ Active engineering work
```

Answers:

- Which goals have active execution?
- Which initiatives have no owner?
- Which work does not connect to a current initiative?
- Where are the critical blockers?

### Product and system view

```text
Product
→ Component
→ Service
→ API / Data Asset
→ Repository
→ Owning Team
```

Answers:

- What implements this product?
- Who owns each part?
- What breaks if this service changes?
- Which systems lack current documentation?

### Initiative view

```text
Initiative
→ Requirements
→ Teams
→ Systems
→ Tasks
→ Pull Requests
→ Evidence
```

Answers:

- Why is this initiative blocked?
- Which requirement has no implementation?
- Which pull request changed the intended scope?

### Risk and policy view

```text
Risk / Policy
→ Affected Products
→ Systems
→ Owners
→ Active Changes
→ Required Controls
```

### Change history view

Show:

- decisions;
- ownership changes;
- architectural changes;
- incidents;
- policy changes;
- merged work;
- knowledge corrections.

## 12.4 Canvas interactions

- Pan and zoom.
- Expand or collapse relationships.
- Filter by entity type, owner, status, time, risk, and freshness.
- Toggle semantic layers.
- Search and focus.
- Open a detail panel.
- Follow provenance.
- View inbound and outbound dependencies.
- Save a view.
- Share a deep link.
- Annotate a view without changing canonical facts.
- Propose a relationship correction.
- Ask Anva a question scoped to the selection.
- Start a governed work item from a selected entity.
- Compare current state with a prior point in time.

## 12.5 Graph-hairball prevention

The default experience must not render the full organization graph.

Use:

- purpose-built saved views;
- typed layers;
- degree limits;
- clustering;
- ownership groups;
- progressive expansion;
- path finding between selected entities;
- "why is this connected?" explanations;
- list and table alternatives.

## 12.6 Node detail panel

Required sections:

- summary;
- owner and reviewers;
- source and freshness;
- active relationships;
- decisions and policies;
- risks and incidents;
- active work and recent pull requests;
- unresolved knowledge conflicts;
- history;
- permitted actions.

## 12.7 Canvas edits

Direct manipulation has different meanings:

- moving a node changes only view layout;
- grouping nodes changes only the view unless explicitly saved as a proposal;
- drawing a relationship creates a relationship proposal;
- editing a canonical property creates an assertion correction;
- deleting a node from the view hides it from the view;
- deleting a canonical entity requires a separate authorized workflow.

The UI must make these distinctions explicit.

## 12.8 Management visibility

Leadership views should aggregate:

- goal coverage;
- initiative health;
- unowned systems;
- unresolved cross-team dependencies;
- stale high-impact knowledge;
- pull-request assurance trends;
- policy exceptions;
- organizational risk.

They must not default to:

- individual commit counts;
- individual agent usage;
- developer rankings;
- time-at-keyboard estimates.

## 12.9 Canvas performance targets

For an initial organization:

- load a standard saved view in under 2 seconds at p95 after shell render;
- render 300 visible nodes without unusable interaction;
- expand a node neighborhood in under 1 second at p95 when cached;
- maintain keyboard-accessible navigation and a non-visual list equivalent;
- avoid loading unauthorized hidden node details into the client.

## 12.10 Canvas acceptance criteria

- Nodes and edges link to canonical Anva records.
- Sources and freshness are visible.
- Users see only permitted entities and excerpts.
- Saved views are versioned.
- Layout edits do not mutate canonical knowledge.
- Relationship edits create reviewable proposals.
- A leader can trace a goal to active engineering work.
- A technical owner can trace a service to dependencies, repositories, and
  recent changes.
- A user can understand why two nodes are connected.
- Large organizations are navigable through layers rather than one full graph.

---

# 13. Web Product Experience

## 13.1 Organization setup

Required:

- organization name and settings;
- membership and roles;
- GitHub App installation;
- source connector selection;
- retention policy;
- model-processing policy;
- skill distribution method;
- default assurance mode.

## 13.2 Onboarding progress

Show:

- repositories selected;
- source containers selected;
- sync status;
- discovered entities;
- unresolved entity matches;
- high-impact review items;
- repository profile status;
- assurance readiness;
- skill installation status.

## 13.3 Home

The home screen should answer:

- What needs attention?
- What changed?
- Is Anva healthy and current?
- Which pull requests are blocked?
- Which knowledge decisions require review?
- Which organizational risks or dependencies became active?

Avoid a dashboard composed only of vanity counters.

## 13.4 Anva Explorer

Support:

- entity search;
- type and owner filters;
- relationship browsing;
- source excerpts;
- revisions;
- conflicts;
- corrections;
- natural-language query;
- transition to Canvas.

## 13.5 Knowledge review inbox

Queues:

- high-impact unreviewed assertions;
- conflicts;
- stale critical assertions;
- correction proposals;
- entity merge proposals;
- post-merge update proposals.

Review actions:

```text
CONFIRM
CORRECT
REJECT
MERGE
SPLIT
MARK_STALE
DEFER
ASSIGN
```

## 13.6 Repository page

Show:

- purpose and owners;
- products and systems;
- repository profile;
- required commands and checks;
- policies;
- sensitive paths;
- recent pull requests and assurance outcomes;
- source health;
- skill setup;
- unresolved knowledge.

## 13.7 Pull-request assurance detail

Show:

- current readiness;
- evaluated commit;
- timeline of runs;
- requirements;
- diff summary;
- deterministic checks;
- evidence;
- findings;
- policy evaluations;
- affected Anva entities;
- human-review focus;
- overrides and dismissals.

## 13.8 Policy page

Show:

- policy list;
- scope;
- versions;
- simulation;
- affected repositories and entities;
- recent evaluations;
- override history.

## 13.9 Skill setup

Show:

- supported hosts;
- install instructions;
- authentication state;
- version compatibility;
- diagnostic result;
- organization-managed distribution option;
- last successful context request.

Do not show raw access tokens.

## 13.10 Audit search

Filter by:

- actor;
- action;
- target;
- source;
- repository;
- pull request;
- policy;
- date;
- request identifier.

## 13.11 Accessibility

- Keyboard navigation for all primary flows.
- Non-canvas alternatives for graph information.
- Visible focus.
- Screen-reader descriptions for nodes and edges.
- Color never carries state alone.
- Reduced-motion support.
- Reports remain useful as semantic HTML and Markdown.

---

# 14. Repository and Organization Onboarding

## 14.1 GitHub inputs

Inspect:

- repository metadata;
- README files;
- documentation directories;
- `CODEOWNERS`;
- package manifests;
- language and framework configuration;
- CI workflows;
- Docker and Compose files;
- infrastructure configuration;
- API schemas;
- migrations;
- test directories;
- browser-test configuration;
- common scripts;
- pull-request templates;
- issue templates;
- selected prior issues and pull requests;
- branch-protection and required checks where permitted.

## 14.2 Generated repository profile

Anva proposes:

- purpose;
- owners;
- products and systems;
- runtime;
- setup commands;
- deterministic checks;
- CI mapping;
- sensitive paths;
- relevant policies;
- documentation sources;
- unsupported or ambiguous setup.

## 14.3 Human confirmation

A technical owner confirms:

- repository purpose;
- owning team;
- supported commands;
- required CI checks;
- sensitive areas;
- policy bindings;
- relevant Anva relationships.

The first vertical slice may use a manually authored profile when automated
detection would delay product validation.

## 14.4 Organization bootstrap

The initial organization map may combine:

- repository-derived systems;
- manually entered goals and initiatives;
- imported organizational documents;
- team and owner confirmation.

Do not delay first value until every system is integrated.

## 14.5 Onboarding exit criteria

- At least one repository is connected and profiled.
- Anva can identify its owning team and product.
- Relevant source documents are indexed with provenance.
- The developer skill retrieves repository context.
- A test pull request triggers assurance.
- Required CI checks can be observed.
- A basic Canvas path connects goal or product to repository and owner.
- Source revocation is tested.

---

# 15. Policy Engine

## 15.1 Policy structure

```yaml
id: backward-compatible-migration
name: Backward-compatible database migration
version: 3
enabled: true

scope:
  organizations:
    - org_iitm
  entity_types:
    - Repository

match:
  paths:
    - "**/migrations/**"

require:
  checks:
    - migration-test
  evidence:
    - rollback-plan
    - compatibility-analysis
  reviewers:
    - role: TECHNICAL_OWNER

severity: blocking
owner: platform-team
```

## 15.2 Policy inputs

- organization;
- repository;
- affected Anva entities;
- changed paths;
- pull-request labels;
- work-item type;
- data classification;
- sensitive-system classification;
- target branch;
- deterministic check results;
- evidence.

## 15.3 Policy outputs

- required checks;
- required evidence;
- required reviewers;
- required approval;
- context to surface;
- blocking or advisory finding;
- report sections;
- expiration or re-evaluation condition.

## 15.4 Policy hierarchy

Suggested precedence:

```text
Organization mandatory policy
→ Product / system policy
→ Repository policy
→ Path-specific policy
```

Lower-level policy may strengthen a mandatory requirement but may not weaken it
without an explicit authorized override.

## 15.5 Policy simulation

Before enabling or changing a policy:

- evaluate it against selected historical pull requests;
- show how many would be blocked;
- show missing check mappings;
- identify ambiguous scope;
- allow the owner to adjust;
- preserve the simulation result.

## 15.6 Overrides

An override records:

- policy version;
- pull request and commit;
- actor and authority;
- reason;
- expiration;
- affected requirement;
- audit event.

## 15.7 Policy acceptance criteria

- Policies are versioned.
- Evaluation is deterministic for the same inputs.
- A run stores exact versions.
- Simulation is available before enforcement.
- Blocking and advisory outcomes remain separate.
- Overrides require reason and authority.
- Model output cannot silently change policy results.
- Policies can refer to Anva entities and repository paths.

---

# 16. Evidence Model

## 16.1 Evidence types

```text
CHECK_STATUS
TEST_RESULT
BUILD_RESULT
TYPECHECK_RESULT
LINT_RESULT
SCREENSHOT
VIDEO
CONSOLE_LOG
NETWORK_TRACE
API_ASSERTION
STATIC_ANALYSIS
SECURITY_SCAN
DEPENDENCY_SCAN
MIGRATION_RESULT
PERFORMANCE_RESULT
ACCESSIBILITY_RESULT
MANUAL_APPROVAL
SOURCE_REFERENCE
DIFF_REFERENCE
```

## 16.2 Evidence fields

```text
organization_id
pull_request_id
commit_sha
type
producer
producer_version
command
status
started_at
completed_at
artifact_reference
content_hash
source_url
limitations
retention_class
```

## 16.3 Criterion mapping

Each `CriterionEvidence` record includes:

- criterion version;
- evidence identifier;
- direct or indirect classification;
- verifier;
- assessment;
- limitations;
- confidence;
- creation time.

## 16.4 Evidence rules

- A prose summary is not evidence by itself.
- A test result identifies command, commit, and result.
- Existing CI status is linked to the exact commit.
- A screenshot identifies scenario and tested state.
- Logs identify environment and time.
- Evidence is immutable after report publication.
- New runs create new evidence records.
- Expired artifacts remain represented by metadata and retention status.
- Secret patterns are redacted before storage or display.

## 16.5 Evidence action security

- Use short-lived, repository-scoped credentials.
- Bind uploads to organization, repository, pull request, and commit.
- Reject oversized or unapproved artifact types.
- Validate manifest schema.
- Scan archive paths and content types.
- Do not execute uploaded files.
- Record content hashes.
- Apply retention policy.

---

# 17. GitHub Integration

## 17.1 Initial permissions

Request the minimum required:

- metadata: read;
- contents: read;
- issues: read and limited write where reports or links are required;
- pull requests: read and write;
- checks: read and write;
- actions: read where required for evidence links;
- members: read only when organization mapping requires it and customer accepts;
- administration: avoid unless a required branch-protection capability cannot be
  achieved otherwise.

Exact permissions must be revalidated against the implemented GitHub App.

## 17.2 Events

Handle:

- installation created, changed, or deleted;
- repositories added or removed;
- repository renamed or archived;
- push to selected branches;
- issue opened or edited;
- issue comment;
- pull request opened;
- pull request edited;
- pull request synchronized;
- pull request converted from draft;
- pull request review;
- pull request closed or merged;
- check suite and check run completion;
- workflow run completion where available.

## 17.3 Idempotency

Store:

- delivery identifier;
- event type;
- organization and repository;
- payload checksum;
- processing state;
- attempts;
- last error;
- resulting domain identifiers.

Duplicate events must not create duplicate:

- entities;
- assurance runs for the same effective trigger;
- comments;
- findings;
- knowledge proposals.

## 17.4 GitHub Check

Use one current Anva Check per evaluated head commit.

The check should contain:

- readiness conclusion;
- short summary;
- blocking count;
- warning count;
- evaluated commit;
- link to detailed report;
- annotations for high-confidence localized findings within platform limits.

## 17.5 Generated-comment marker

```html
<!-- anva:pr=PR_ID report=assurance commit=SHA -->
```

Update Anva-generated content without deleting human discussion.

## 17.6 Forks and untrusted contributions

- Never expose Anva tokens to untrusted fork workflows.
- Server-side evaluation may read a public or authorized diff without executing
  it.
- Evidence uploaded from workflows receiving secrets must follow GitHub's
  security model.
- Treat pull-request text and code as prompt-injection content.
- Do not automatically fetch or execute artifacts from untrusted origins.

## 17.7 Revocation

When a GitHub installation or repository is removed:

- stop future sync and assurance;
- revoke associated tokens;
- mark source health revoked;
- enforce configured retention;
- preserve required audit metadata;
- prevent new skill context retrieval for the repository.

---

# 18. API and MCP Surface

The exact URL structure may change. Capabilities and authorization requirements
must remain.

## 18.1 Organizations and membership

```text
POST   /api/organizations
GET    /api/organizations/{id}
GET    /api/organizations/{id}/members
POST   /api/organizations/{id}/members
PUT    /api/memberships/{id}
DELETE /api/memberships/{id}
```

## 18.2 Sources

```text
POST   /api/organizations/{id}/source-connections
GET    /api/source-connections/{id}
POST   /api/source-connections/{id}/authorize
POST   /api/source-connections/{id}/sync
POST   /api/source-connections/{id}/revoke
GET    /api/source-connections/{id}/health
GET    /api/sync-runs/{id}
```

## 18.3 Repositories

```text
GET    /api/organizations/{id}/repositories
POST   /api/repositories/{id}/onboard
GET    /api/repositories/{id}/profile
PUT    /api/repositories/{id}/profile
POST   /api/repositories/{id}/profile/validate
GET    /api/repositories/{id}/anva-summary
```

## 18.4 Anva entities and relationships

```text
GET    /api/entities
POST   /api/entities
GET    /api/entities/{id}
GET    /api/entities/{id}/relationships
GET    /api/entities/{id}/history
GET    /api/entities/{id}/sources
POST   /api/entities/{id}/corrections
POST   /api/relationship-proposals
GET    /api/knowledge-review
POST   /api/knowledge-review/{id}/decisions
```

## 18.5 Search and context

```text
POST   /api/search
POST   /api/context-packets
GET    /api/context-packets/{id}
POST   /api/query
GET    /api/assertions/{id}/explanation
```

## 18.6 Work items and requirements

```text
POST   /api/work-items
GET    /api/work-items/{id}
GET    /api/work-items/{id}/requirements
POST   /api/work-items/{id}/requirements
POST   /api/work-items/{id}/approvals
POST   /api/work-items/{id}/work-summaries
```

## 18.7 Pull requests and assurance

```text
GET    /api/pull-requests/{id}
GET    /api/pull-requests/{id}/assurance-runs
POST   /api/pull-requests/{id}/assurance-runs
GET    /api/assurance-runs/{id}
GET    /api/assurance-runs/{id}/evidence
GET    /api/assurance-runs/{id}/findings
POST   /api/findings/{id}/resolve
POST   /api/findings/{id}/dismiss
POST   /api/findings/{id}/accept-risk
POST   /api/pull-requests/{id}/evidence
```

## 18.8 Policies

```text
GET    /api/policies
POST   /api/policies
GET    /api/policies/{id}
POST   /api/policies/{id}/versions
POST   /api/policies/{id}/simulate
POST   /api/policy-evaluations/{id}/override
```

## 18.9 Canvas

```text
GET    /api/canvas-views
POST   /api/canvas-views
GET    /api/canvas-views/{id}
PUT    /api/canvas-views/{id}
POST   /api/canvas-views/{id}/revisions
POST   /api/canvas/query
POST   /api/canvas/path
```

## 18.10 Skills

```text
GET    /api/skill-distributions
GET    /api/skill-distributions/{host}/latest
POST   /api/skill-sessions/diagnose
GET    /api/skill-compatibility
```

## 18.11 Webhooks and callbacks

```text
POST   /webhooks/github
POST   /callbacks/evidence
POST   /callbacks/source/{connection_id}
```

## 18.12 MCP resources

Potential resources:

```text
anva://organizations/{organization_id}/repositories/{repository_id}/profile
anva://work-items/{work_item_id}/requirements
anva://entities/{entity_id}
anva://context-packets/{packet_id}
```

Use MCP tools for parameterized search and proposals. Use resources for stable,
addressable context where supported.

## 18.13 API requirements

- OpenAPI for HTTP endpoints.
- JSON Schema for context, evidence, findings, and proposals.
- MCP tool input and output schemas.
- Organization and object authorization on every request.
- Idempotency keys for externally retried writes.
- Pagination and bounded response size.
- Consistent structured errors.
- Audit events for mutations.
- Rate limits by organization, actor, and integration identity.
- Correlation identifiers across GitHub, API, MCP, and assurance jobs.

---

# 19. Authentication and Authorization

## 19.1 Authentication methods

- Web user authentication.
- GitHub identity connection.
- OAuth for supported remote MCP clients.
- GitHub App installation credentials.
- Short-lived evidence-upload identity.
- Internal service identity.

## 19.2 Authorization dimensions

Decisions may depend on:

- organization membership;
- role;
- team;
- repository access;
- source access;
- entity classification;
- action;
- policy-defined approver;
- current source permission snapshot.

## 19.3 Retrieval authorization

A context packet may include an item only when:

- the actor may access the source-derived content;
- the repository may receive the context under organization policy;
- the requested phase justifies it;
- the item is within the configured data boundary.

## 19.4 Derived information

Derived assertions can leak source information.

Therefore every derived assertion must carry an access scope based on:

- contributing sources;
- organization policy;
- human review;
- deliberate declassification where supported.

Combining sources must not automatically widen visibility.

## 19.5 Approval authority

Approval may be scoped by:

- product;
- team;
- repository;
- policy;
- entity type;
- security classification.

## 19.6 Service-to-service authorization

- Use distinct service identities.
- Validate audience and issuer.
- Rotate credentials.
- Scope evidence upload to exact repository and commit where possible.
- Prevent the PR Assurance worker from accessing unrestricted administration
  APIs.

## 19.7 Authorization acceptance criteria

- Cross-tenant requests fail.
- Repository access is enforced for context retrieval.
- Source revocation changes future retrieval.
- Derived assertions do not widen source visibility.
- Unauthorized users cannot dismiss blocking findings.
- Policy override authority is tested.
- Signed artifact links expire.
- Every decision records its authorization path.

---

# 20. Security and Privacy

## 20.1 Threat model

Assume malicious or misleading content may exist in:

- source code;
- repository documentation;
- issues and pull-request text;
- commit messages;
- source documents;
- generated test logs;
- uploaded evidence manifests;
- model output;
- developer skill output;
- MCP tool arguments.

Assume integrations can be revoked, misconfigured, or compromised.

## 20.2 Required controls

- Tenant isolation.
- Least-privilege GitHub permissions.
- Permission-aware retrieval.
- Short-lived tokens.
- Secret redaction.
- Encryption in transit and at rest.
- Verified webhooks.
- Idempotent event processing.
- Strict schema validation.
- Artifact size and type limits.
- Prompt-injection separation.
- Append-only application audit.
- Configurable retention and deletion.
- Model-processing data policy.
- Rate limits and abuse protection.
- Dependency and container scanning.

## 20.3 Prompt-injection controls

- Label repository and source content as untrusted.
- Keep evaluator instructions separate from retrieved content.
- Tool authorization occurs outside the model.
- Models cannot request broader context than server authorization permits.
- Do not expose secret values in prompts.
- Quote or delimit source excerpts.
- Surface suspicious instructions as content.
- Require citations for model findings.
- Validate structured outputs.
- Test indirect injection from code, issues, docs, and logs.

## 20.4 Skill supply-chain security

- Sign or checksum released skill packages.
- Publish version and source repository.
- Pin stable versions in organization-managed deployments.
- Minimize executable scripts.
- Review every bundled script and hook.
- Declare network and tool dependencies.
- Avoid post-install scripts where possible.
- Keep write-capable MCP tools approval-gated.
- Provide a read-only deployment mode.
- Maintain a security contact and revocation mechanism.

## 20.5 Model data governance

Per organization, record:

- selected inference provider;
- regions where available;
- retention and training terms accepted by the organization;
- whether source excerpts may be sent;
- prohibited classifications;
- redaction requirements;
- maximum context size.

If a source item cannot be sent to the configured model, deterministic policy
and metadata-only evaluation may still run, but the limitation must be visible.

## 20.6 Sensitive organizational domains

Initial Anva should avoid ingesting:

- employee performance records;
- medical or benefits data;
- legal-privileged content;
- unrestricted production secrets;
- customer credentials;
- private executive communications;

unless a later explicitly designed product boundary supports them.

## 20.7 Logging

- Never log authorization headers.
- Never log raw tokens.
- Avoid environment dumps.
- Redact configured secret patterns.
- Store model input/output only according to retention policy.
- Prefer identifiers and hashes in operational logs.
- Record access and deletion events.

## 20.8 Deletion

Support:

- source disconnection;
- source-derived content deletion;
- organization deletion;
- user identity deletion or anonymization where legally required;
- artifact expiry;
- audit-preservation rules.

Deletion must account for derived assertions and embeddings, not only raw source
rows.

## 20.9 Security acceptance criteria

- A malicious source cannot change authorization policy.
- A pull request cannot access unrelated organization context.
- An untrusted fork cannot receive Anva secrets.
- Revoked source access is enforced.
- Secret-pattern tests show no leakage in logs or reports.
- Skill proposals cannot directly approve themselves.
- Model output cannot mark a deterministic check passed.
- Uploaded evidence cannot trigger code execution.
- Cross-tenant tests cover API, search, Canvas, MCP, and artifacts.
- A threat-model review is completed before adding each new source connector.

---

# 21. Technical Architecture

## 21.1 Recommended monorepo

```text
/
├── apps/
│   ├── control_plane/             # Django + DRF
│   └── web/                       # Next.js + TypeScript
├── services/
│   ├── mcp_gateway/               # Remote authenticated Anva MCP
│   ├── ingestion_worker/          # Source fetch and extraction
│   ├── assurance_worker/          # PR evaluation jobs
│   └── github_worker/             # Webhook and outbound GitHub operations
├── packages/
│   ├── contracts/                 # OpenAPI, JSON Schema, generated clients
│   ├── ontology/                  # Entity and relationship vocabulary
│   ├── policy_engine/
│   ├── report_templates/
│   ├── brain_skills/
│   │   ├── workflows/
│   │   ├── hosts/
│   │   │   ├── codex/
│   │   │   └── claude_code/
│   │   └── evals/
│   └── evaluation_prompts/
├── integrations/
│   ├── github/
│   ├── sources/
│   │   ├── repository/
│   │   └── design_partner_documents/
│   └── evaluators/
│       ├── fake/
│       └── initial/
├── actions/
│   └── evidence/
├── infra/
│   ├── terraform/
│   └── docker/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── e2e/
│   ├── security/
│   ├── retrieval_evals/
│   ├── assurance_evals/
│   └── skill_evals/
├── fixtures/
│   ├── reference_organization/
│   └── reference_repositories/
├── docs/
│   ├── adrs/
│   ├── api/
│   ├── product/
│   ├── runbooks/
│   ├── security/
│   └── skills/
├── scripts/
├── Makefile
└── README.md
```

## 21.2 Backend

- Python 3.12 or later.
- Django.
- Django REST Framework.
- PostgreSQL.
- pgvector for semantic retrieval.
- Database-backed state and job records.
- Transactional outbox for durable external dispatch.
- Cloud Tasks or equivalent lightweight managed dispatch.
- Object storage for retained raw sources, diffs, and evidence artifacts.
- OpenTelemetry.

Do not introduce a general workflow engine initially.

## 21.3 Frontend

- Next.js.
- TypeScript.
- Generated API client.
- React Query or equivalent server-state library.
- Accessible component system.
- A mature graph/canvas rendering library selected through a short prototype.
- Server-rendered application shell where useful.
- Virtualized lists and detail panels for large result sets.

The Canvas library must not become the canonical graph model.

## 21.4 Search

Use PostgreSQL for:

- structured filters;
- full-text search;
- trigram or normalized-name matching;
- vector similarity;
- relationship traversal through indexed tables.

Add a dedicated search engine only if measured scale, latency, or ranking quality
requires it.

## 21.5 Relationship traversal

Initial traversals should be explicit bounded queries:

- one-hop neighborhood;
- typed multi-hop paths up to configured depth;
- shortest permitted path between two entities;
- saved-view queries;
- ownership and dependency closure with cycle protection.

Do not permit arbitrary unbounded recursive queries from the public API.

## 21.6 Source processing

Recommended stages:

- connector fetch;
- immutable source-revision record;
- parser selected by source type;
- normalized text and metadata;
- access snapshot;
- chunks;
- embeddings;
- candidate extraction;
- entity resolution;
- assertion publication or review.

Each stage stores:

- input version;
- implementation version;
- output version;
- status;
- duration;
- error category.

## 21.7 Reasoning and embedding providers

Use separate small interfaces:

- `EmbeddingProvider`;
- `ExtractionEvaluator`;
- `AssuranceEvaluator`;
- `AnswerGenerator`.

These are stateless model calls, not agent runtimes.

The initial implementation may share one provider configuration while preserving
separate prompts, schemas, budgets, and evaluation datasets.

## 21.8 Background jobs

Required job types:

```text
SOURCE_DISCOVERY
SOURCE_FETCH
SOURCE_PARSE
SOURCE_INDEX
ENTITY_EXTRACTION
ENTITY_RESOLUTION
ASSERTION_EXTRACTION
KNOWLEDGE_CONFLICT_SCAN
KNOWLEDGE_FRESHNESS_SCAN
GITHUB_EVENT_PROCESS
PR_DIFF_FETCH
ASSURANCE_DETERMINISTIC
ASSURANCE_CONTEXT
ASSURANCE_MODEL_REVIEW
ASSURANCE_REPORT
POST_MERGE_LEARNING
OUTBOUND_GITHUB_WRITE
RETENTION_DELETE
```

Every job must:

- accept identifiers rather than serialized domain objects;
- be idempotent;
- record attempts;
- distinguish transient from terminal failure;
- honor tenant rate limits;
- propagate correlation identifiers;
- support safe cancellation where useful.

## 21.9 Transactional outbox

Use an outbox record when a database mutation requires:

- task dispatch;
- GitHub write;
- source callback;
- notification;
- audit export.

The mutation and outbox record must commit in one transaction.

## 21.10 Object storage

Potential objects:

- raw authorized source revisions;
- parsed source artifacts;
- pull-request diffs;
- evidence reports;
- screenshots or videos uploaded from CI;
- rendered reports.

Store metadata, hashes, access class, and retention state in PostgreSQL.

## 21.11 Cloud

Optimized for the founder's GCP experience:

- Cloud Run for API, web, MCP gateway, and stateless workers.
- Cloud SQL for PostgreSQL.
- Google Cloud Storage for artifacts.
- Secret Manager for secret references.
- Cloud Tasks for dispatch.
- Pub/Sub only where event fan-out justifies it.
- Cloud Logging and OpenTelemetry.
- Terraform.

## 21.12 Environments

```text
local
test
staging
production
```

Requirements:

- separate cloud projects or equivalent strong isolation for production;
- separate databases and buckets;
- no production source content in ordinary local development;
- anonymized or synthetic evaluation fixtures;
- explicit migration and rollback procedure.

## 21.13 Schema strategy

- Use UUID or opaque identifiers.
- Include `organization_id` on tenant-owned rows where appropriate.
- Enforce tenant and uniqueness constraints in the database.
- Store timestamps in UTC.
- Use explicit revision tables for governed records.
- Use immutable artifact/evidence rows.
- Use soft deletion only where retention and recovery require it.
- Avoid generic entity-attribute-value storage for critical business data.

## 21.14 API versioning

- Version external HTTP and MCP contracts.
- Version JSON schemas independently.
- Provide capability discovery.
- Maintain one previous stable skill/MCP contract during private beta.
- Reject unsupported schema versions with actionable errors.

## 21.15 Performance budgets

Initial targets:

- authenticated API reads under 400 ms p95 excluding source fetch and model work;
- Anva search under 1 second p95 for initial design-partner scale;
- context packet generation under 5 seconds p95 without cold model extraction;
- GitHub webhook acknowledgement under 2 seconds;
- assurance status visible within 30 seconds of an eligible trigger;
- typical model-assisted assurance complete within 5 minutes;
- no request thread blocked on long-running model work.

Targets must be revised from production measurements.

---

# 22. State Machines and Invariants

## 22.1 Source connection state

```text
DRAFT
AUTHORIZING
ACTIVE
DEGRADED
REVOKED
DISABLED
FAILED
```

## 22.2 Sync run state

```text
REQUESTED
DISCOVERING
FETCHING
PARSING
INDEXING
EXTRACTING
RESOLVING
PUBLISHING
COMPLETED
PARTIALLY_COMPLETED
FAILED
CANCELLED
```

## 22.3 Assertion review state

```text
UNREVIEWED
AUTO_ACCEPTED
HUMAN_CONFIRMED
DISPUTED
REJECTED
SUPERSEDED
STALE
```

## 22.4 Assurance run state

```text
REQUESTED
DEBOUNCING
FETCHING_PULL_REQUEST
COLLECTING_EVIDENCE
EVALUATING_POLICY
BUILDING_CONTEXT
MODEL_REVIEW
MAPPING_EVIDENCE
RENDERING_REPORT
PUBLISHING
COMPLETED
STALE
FAILED
CANCELLED
```

## 22.5 Knowledge proposal state

```text
PROPOSED
VALIDATING
AWAITING_REVIEW
ACCEPTED
REJECTED
SUPERSEDED
FAILED
```

## 22.6 State invariants

- No transition occurs without an audit event.
- No assurance run reports on a different commit than the one it evaluated.
- No criterion is satisfied without evidence or an explicit manual approval
  allowed by policy.
- No policy evaluation omits its policy version.
- No reviewed assertion is silently overwritten.
- No source-derived context outlives authorization without a retention decision.
- No external comment or Check is published without storing rendered content and
  external identifiers.
- No retry deletes prior attempt history.
- No model output directly mutates approved knowledge.
- No skill proposal is represented as accepted before review.

## 22.7 Concurrency rules

- Only one current assurance summary exists per pull-request head commit.
- Multiple internal evaluation attempts may exist.
- A newer head commit marks older active runs stale.
- A knowledge review decision uses optimistic concurrency against the proposal
  version.
- Source sync uses per-connection leases or equivalent protection.
- Outbound GitHub writes use idempotency keys.

---

# 23. Testing and Evaluation Strategy

## 23.1 Testing principle

This product's value depends on trust. Testing must cover deterministic software
behavior and model-assisted quality.

Passing application tests does not prove retrieval, skill, or assurance quality.
Those require explicit evaluation datasets.

## 23.2 Unit tests

Cover:

- authorization;
- state-transition guards;
- relationship validation;
- source revision logic;
- entity resolution rules;
- assertion conflict rules;
- freshness calculation;
- context budget selection;
- policy evaluation;
- readiness calculation;
- finding fingerprints;
- evidence mapping;
- report rendering;
- webhook parsing;
- secret redaction;
- Canvas query construction.

## 23.3 Integration tests

Cover:

- PostgreSQL persistence and constraints;
- pgvector retrieval;
- source-sync resumption;
- transactional outbox;
- GitHub webhook idempotency;
- GitHub Check publication;
- OAuth and MCP authorization;
- source revocation;
- model adapter structured output;
- evidence upload;
- report regeneration;
- retention deletion.

## 23.4 Contract tests

Cover:

- GitHub webhook fixtures;
- GitHub API client behavior;
- source connector payloads;
- MCP tool schemas;
- HTTP OpenAPI;
- context packet schema;
- evidence manifest schema;
- finding schema;
- policy schema;
- skill output schemas;
- generated TypeScript client.

## 23.5 End-to-end tests

Use the fake evaluator for deterministic product flows:

1. Create organization.
2. Install fake or test GitHub connection.
3. Onboard repository.
4. Ingest source.
5. Review an assertion.
6. Query Anva.
7. Open a Canvas view.
8. Authenticate a test MCP client.
9. Retrieve a context packet.
10. Create a pull request.
11. Observe CI checks.
12. Produce assurance.
13. Resolve a finding.
14. Merge.
15. Review a post-merge knowledge proposal.

## 23.6 Security tests

Cover:

- cross-tenant API access;
- cross-tenant semantic search;
- cross-tenant Canvas traversal;
- unauthorized MCP retrieval;
- derived-assertion access leakage;
- source revocation;
- expired OAuth token;
- malicious webhook;
- duplicate webhook;
- prompt injection in every source class;
- malicious evidence archive;
- path traversal;
- unauthorized finding dismissal;
- unauthorized policy override;
- token and secret redaction;
- untrusted fork behavior.

## 23.7 Retrieval evaluations

Create a labeled reference organization containing:

- goals and initiatives;
- teams and systems;
- repositories;
- decisions;
- policies;
- conflicting documents;
- stale facts;
- incidents;
- tasks and pull requests.

For representative requests, label:

- required context;
- relevant optional context;
- prohibited context;
- stale or misleading context;
- expected source links.

Metrics:

- required-context recall;
- precision at packet budget;
- prohibited-context rate;
- stale-context rate;
- source-link correctness;
- ranking stability.

## 23.8 Skill evaluations

Run the same semantic scenarios against supported host versions.

Scenario classes:

- clear feature;
- ambiguous feature;
- missing owner;
- conflicting decision;
- security-sensitive change;
- database migration;
- browser change;
- Anva unavailable;
- revoked authorization;
- malicious repository instruction;
- user-requested scope expansion.

Judge:

- context retrieval;
- requirement quality;
- assumption separation;
- adherence to policy;
- scope discipline;
- preflight completeness;
- proposal correctness;
- claim grounding.

## 23.9 Assurance evaluations

Fixture pull requests should contain:

- correct implementation;
- missing test;
- wrong requirement;
- hidden scope expansion;
- compatibility break;
- unsafe migration;
- security regression;
- misleading pull-request description;
- unrelated failing CI;
- stale Anva claim;
- harmless pattern likely to cause false positives.

Label expected:

- blocking findings;
- advisory findings;
- non-findings;
- criterion evidence;
- affected systems;
- review focus.

Metrics:

- blocking finding recall;
- blocking false-positive rate;
- advisory precision;
- unsupported finding rate;
- source citation correctness;
- stable-fingerprint accuracy;
- criterion-mapping accuracy;
- readiness accuracy;

## 23.10 Model regression gates

Before changing:

- model;
- system prompt;
- context-packet format;
- chunking;
- retrieval ranking;
- output schema;

run the relevant evaluation suite and compare with the approved baseline.

A change must not ship when:

- security leakage increases;
- blocking false positives materially increase;
- required-context recall materially decreases;
- unsupported claims exceed threshold;
- readiness accuracy regresses beyond agreed tolerance.

## 23.11 Fake evaluator

Support deterministic scenarios:

```text
SUCCESS_NO_FINDINGS
SUCCESS_WITH_ADVISORY
SUCCESS_WITH_BLOCKING
MALFORMED_OUTPUT
TIMEOUT
RATE_LIMITED
PARTIAL_OUTPUT
UNSUPPORTED_CITATION
INJECTION_COMPLIANCE_ATTEMPT
```

## 23.12 Reference repositories

Maintain small repositories containing:

- Django backend;
- browser-visible frontend;
- PostgreSQL migration;
- API schema;
- CI workflows;
- CODEOWNERS;
- seeded requirement gaps;
- seeded security issues;
- seeded architecture-policy violations;
- clean pull-request fixtures.

## 23.13 Golden tests

Use golden files for:

- GitHub reports;
- context packet rendering;
- policy explanations;
- audit summaries;
- source citations;
- skill outputs where deterministic;
- Canvas saved-view serialization.

Golden changes require review and should not conceal semantic regressions.

## 23.14 Definition of test completion

A feature is not complete unless:

- business logic has unit coverage;
- persisted behavior has integration coverage;
- authorization is tested;
- failure and retry paths are tested;
- external schemas have contract tests;
- relevant user flow passes end to end;
- model-assisted behavior has an evaluation scenario;
- observability exists;
- documentation is updated;
- no test or eval is disabled without explanation.

---

# 24. Observability and Operations

## 24.1 Product metrics

- organizations onboarded;
- repositories activated;
- active skill users;
- context packets requested;
- pull requests evaluated;
- pull requests ready on first assurance run;
- time from pull-request open to review readiness;
- knowledge corrections;
- recurring use by organization.

## 24.2 Anva quality metrics

- assertions by review state;
- conflict count;
- stale high-impact assertions;
- source freshness;
- source sync failures;
- correction acceptance rate;
- entity-resolution ambiguity;
- context retrieval relevance;
- provenance coverage.

## 24.3 Assurance metrics

- blocking finding rate;
- advisory finding rate;
- false-positive rate;
- finding dismissal reasons;
- readiness by first and later run;
- criteria with evidence;
- policy override rate;
- assurance latency;
- stale run count;
- reviewer interaction with reports.

## 24.4 Skill metrics

Collect only organization-approved operational events:

- install/version;
- authentication success;
- context request;
- workflow name;
- MCP error category;
- structured proposal submission.

Do not collect raw prompts, source code, or conversation transcripts by default.

## 24.5 Cost metrics

- model cost per source revision;
- model cost per context packet where applicable;
- model cost per assurance run;
- embedding cost;
- storage per organization;
- GitHub API usage;
- cost per pull request reaching readiness;

## 24.6 Tracing

A trace should connect:

```text
GitHub webhook
→ pull-request revision
→ evidence collection
→ policy evaluation
→ context packet
→ model evaluation
→ finding persistence
→ report render
→ GitHub Check publication
```

Source trace:

```text
source sync
→ source revision
→ parse
→ extraction
→ entity resolution
→ assertion
→ review or publication
→ retrieval
```

## 24.7 Alerts

Alert on:

- webhook backlog;
- repeated GitHub write failure;
- stale active assurance runs;
- source sync failure threshold;
- source authorization failure;
- model-provider outage;
- abnormal cross-tenant authorization denials;
- evidence upload failure;
- retention deletion failure;
- unexpected secret-redaction event;
- cost anomaly;
- retrieval latency or error spike.

## 24.8 Runbooks

Required:

- GitHub outage;
- model-provider outage;
- source connector outage;
- stuck assurance run;
- duplicate or incorrect report;
- suspected permission leak;
- source revocation;
- credential rotation;
- tenant deletion;
- model regression rollback;
- database restore;
- incident communication.

---

# 25. Product Metrics and Success Criteria

## 25.1 North-star metric

Recommended:

> Percentage of eligible pull requests that are ready for serious human review
> on the first assurance run, without requirement-related rework.

Eligibility must exclude:

- unsupported repositories;
- automated dependency pull requests unless separately evaluated;
- pull requests without configured CI during early onboarding;
- intentionally experimental work;
- known infrastructure outages.

## 25.2 Supporting outcome metrics

- requirement-related revision rate;
- median human review time;
- time spent locating organizational context;
- percentage of criteria with credible evidence;
- percentage of findings accepted as useful;
- time to identify an owner or dependency;
- percentage of high-impact Anva assertions reviewed;
- recurring weekly use.

## 25.3 IITM pilot targets

Targets after baseline measurement:

- At least 70% of eligible pull requests reach
  `READY_FOR_HUMAN_REVIEW` or `READY_WITH_WARNINGS` on the first run.
- At least 90% of evaluated pull requests have a complete assurance audit
  history.
- At least 90% of approved acceptance criteria map to evidence or explicit gaps.
- At least 80% of sampled context packets are rated useful by developers.
- Blocking false-positive rate is low enough that reviewers continue using the
  report; establish a numeric threshold from the first 30 evaluated pull
  requests.
- Requirement-related rework decreases from the measured baseline.
- No unauthorized context disclosure.
- No autonomous merge or deployment.

## 25.4 Commercial beta targets

- Standard GitHub onboarding in under two hours excluding customer approvals.
- First useful context packet within one day.
- First PR assurance result within the onboarding session.
- Three non-IITM design customers before broad organizational expansion.
- Repeated weekly use in multiple repositories.
- Expansion from developer skill usage to leadership Canvas usage.
- Viable gross margin after inference and storage cost.

## 25.5 Guardrail metrics

- false-positive rate;
- source-access violations;
- stale critical context rate;
- policy override rate;
- skill-trigger failure rate;
- report-ignore rate;
- average model cost per pull request;
- employee-surveillance feature requests declined or redirected.

## 25.6 Avoid vanity metrics

Do not optimize primarily for:

- graph node count;
- embeddings created;
- tokens consumed;
- findings produced;
- lines of code reviewed;
- individual developer agent usage;
- dashboard visits without completed jobs.

---

# 26. Rollout Strategy

## 26.1 Stage 0: Internal fixture

- Synthetic reference organization.
- Reference repositories.
- Fake evaluator.
- No external users.

Exit:

- Complete vertical flow works deterministically.

## 26.2 Stage 1: IITM shadow mode

Anva:

- ingests selected sources;
- supplies skill context to a small group;
- evaluates pull requests;
- does not publish blocking GitHub conclusions;
- compares results with human review.

Measure:

- context usefulness;
- missing context;
- false positives;
- missed findings;
- review overlap;
- setup friction.

## 26.3 Stage 2: IITM advisory mode

- Anva publishes neutral or advisory Checks.
- Developers use skills in real work.
- Reviewers resolve and dismiss findings.
- Knowledge corrections enter normal workflow.

## 26.4 Stage 3: Selected policy enforcement

Only high-confidence deterministic policies become required:

- required CI checks;
- required reviewer;
- required migration evidence;
- requirement linkage for selected work.

Model-generated findings remain advisory unless separately confirmed by a
deterministic policy or authorized human.

## 26.5 Stage 4: Multi-team IITM

- Multiple repositories and teams.
- Cross-repository dependency visibility.
- Leadership Canvas views.
- Measured reduction in requirement-related rework.

## 26.6 Stage 5: Commercial private beta

- Multi-tenant hardening.
- Standard onboarding.
- Contractual retention and model-processing settings.
- Usage and billing.
- Support tooling.

## 26.7 Intervention categories

```text
MISSING_SOURCE
BAD_ENTITY_RESOLUTION
STALE_ASSERTION
PERMISSION_MISMATCH
IRRELEVANT_CONTEXT
MISSING_CONTEXT
SKILL_TRIGGER_FAILURE
SKILL_WORKFLOW_FAILURE
GITHUB_MAPPING_FAILURE
CI_EVIDENCE_GAP
ASSURANCE_FALSE_POSITIVE
ASSURANCE_FALSE_NEGATIVE
POLICY_CONFIGURATION_ERROR
MODEL_FAILURE
HUMAN_PREFERENCE
UNSUPPORTED_WORKFLOW
```

Every founder intervention should use one primary category and optional detail.

---

# 27. Milestone Roadmap

The roadmap favors an early vertical slice over broad infrastructure.

Milestones may overlap only where explicitly stated. Exit criteria, not dates,
control progression.

# Milestone 0 — Decisions and engineering foundation

## Target

Week 1

## Goal

Create a reproducible product foundation and resolve the decisions that would
otherwise cause architectural churn.

Implementation scope:

- `FND-001` through `FND-012`.

## Deliverables

- Monorepo.
- Backend and frontend bootstrap.
- PostgreSQL and pgvector.
- Local development.
- CI.
- Formatting, linting, type checking, and tests.
- Contract-generation skeleton.
- ADR structure.
- Threat-model template.
- Synthetic reference organization.
- Reference repository.
- Final choice of initial external document source.
- Final choice of initial model provider for extraction and assurance.

## Exit criteria

- A new developer or coding agent can run the project from the README.
- CI passes.
- Test data is isolated.
- Core contracts can be generated.
- Product boundaries in Sections 2 and 4 are accepted.
- No coding-agent runtime or customer-code sandbox is introduced.

# Milestone 1 — End-to-end thin vertical slice

## Target

Weeks 2–4

## Goal

Prove the complete product loop on one reference repository with manually seeded
Anva data.

Implementation scope:

- `VSL-001` through `VSL-010`.

## Deliverables

- Organization and membership.
- GitHub App installation.
- One repository connection.
- Minimal repository profile.
- Manually seeded product, team, repository, decision, and policy entities.
- Basic context-packet API.
- Minimal authenticated Anva MCP server.
- One prepare/preflight skill for Codex.
- Equivalent skill for Claude Code.
- Pull-request webhook handling.
- Existing GitHub Check observation.
- Fake evaluator.
- One Anva assurance Check and report.
- Minimal entity list and relationship view.

## Exit criteria

- A developer retrieves Anva context from Codex and Claude Code.
- A pull request triggers assurance without Anva executing repository code.
- The report links a requirement, a policy, CI state, and a Anva source.
- A merged pull request creates a knowledge-update proposal.
- Duplicate webhook delivery is safe.
- The flow works end to end in the reference organization.

# Milestone 2 — Trustworthy Anva ingestion

## Target

Weeks 5–8

## Goal

Replace manual seeding for supported sources with provenance-aware ingestion and
review.

Primary implementation scope:

- `BRN-*`
- `SRC-*`
- `ONB-*`
- `CTX-*`

## Deliverables

- Repository scanning.
- Repository source revisions.
- Selected document connector.
- Parsing and indexing.
- Entity extraction and resolution.
- Assertion extraction.
- Provenance.
- Confidence and inference labeling.
- Knowledge-review inbox.
- Conflict and correction handling.
- Source health.
- Revocation.
- Initial semantic retrieval.

## Exit criteria

- IITM sources create reviewable entities and assertions.
- Critical claims link to source locations.
- Ambiguous entity matches enter review.
- A correction changes future context without deleting history.
- Revoked content is excluded from future retrieval.
- Retrieval evaluations meet an agreed baseline.

# Milestone 3 — Production developer skills and MCP

## Target

Weeks 7–10, overlapping Milestone 2

## Goal

Make Anva useful inside the developer's existing agent with safe, supportable
installation.

Primary implementation scope:

- `MCP-*`
- `SKL-*`
- production hardening of the Milestone 1 skill path.

## Deliverables

- `anva-prepare`.
- `anva-build`.
- `anva-preflight`.
- `anva-learn`.
- Codex plugin/distribution.
- Claude Code skill/distribution.
- OAuth for remote MCP.
- MCP capability discovery.
- Installation diagnostics.
- Skill versioning.
- Host-specific test harnesses.
- Skill evaluation suite.
- Organization-managed distribution documentation.

## Exit criteria

- IITM developers can install and authenticate without founder intervention.
- Both hosts retrieve equivalent authorized task context.
- Skills degrade safely when Anva is unavailable.
- Write operations create proposals.
- No organization secrets are packaged in skills.
- Skill evals meet accepted grounding and scope thresholds.

# Milestone 4 — Pull-request assurance

## Target

Weeks 9–13

## Goal

Deliver trustworthy, independent, source-backed pull-request evaluation.

Primary implementation scope:

- `WRK-*`
- `POL-*`
- `EVD-*`
- `ASR-*`
- production hardening of `GIT-*`.

## Deliverables

- Pull-request revision model.
- Assurance state machine.
- CI Check ingestion.
- Policy evaluation.
- Evidence model.
- Anva Evidence Action.
- Structured model evaluator.
- Diff analysis and chunking.
- Requirement coverage.
- Finding lifecycle.
- Readiness calculation.
- GitHub Check and report.
- Re-evaluation.
- Post-merge proposals.
- Assurance evaluation suite.

## Exit criteria

- Every readiness decision is reproducible from stored inputs.
- Required deterministic failures block readiness.
- Model findings cite sources or diff locations.
- Every acceptance criterion maps to evidence or a gap.
- False-positive baseline is measured on IITM pull requests.
- Re-evaluation after a new commit preserves history.
- No autonomous merge or deployment.

# Milestone 5 — Organizational Canvas

## Target

Weeks 11–15, overlapping late Milestone 4

## Goal

Make Anva legible and useful to technical owners and engineering leadership.

Primary implementation scope:

- `CAN-*`
- `WEB-*`

## Deliverables

- Anva Explorer.
- Entity detail.
- Strategy view.
- Product and system view.
- Initiative view.
- Risk and policy layer.
- Saved views.
- Provenance and freshness overlays.
- Path finding.
- Time comparison.
- Relationship proposals.
- Accessible list alternative.

## Exit criteria

- A leader can trace an initiative to teams, systems, and active pull requests.
- A technical owner can inspect dependencies and recent changes.
- Every displayed canonical relationship is explainable.
- Layout changes do not mutate knowledge.
- Permission tests cover Canvas queries.
- Standard views meet performance budgets.

# Milestone 6 — IITM production hardening

## Target

Weeks 14–20

## Goal

Move from supervised product testing to sustained real use across multiple IITM
repositories.

Primary implementation scope:

- `SEC-*`
- `OPS-*` required for the pilot.
- hardening and remediation issues discovered in shadow mode.

## Deliverables

- Shadow and advisory rollout.
- Source and assurance runbooks.
- Cost controls.
- Rate limits.
- Retention configuration.
- Operational alerts.
- Model-regression process.
- Policy simulation.
- Support tools.
- Multi-team permissions.
- Pilot metrics dashboard.
- Security review.

## Exit criteria

- Multiple IITM teams use skills weekly.
- Eligible pull requests reach the initial readiness target.
- Context is rated useful at the pilot threshold.
- Blocking false positives remain within the accepted threshold.
- Audit completeness meets target.
- No cross-repository or cross-user context leak.
- Founder intervention is categorized and declining.

# Milestone 7 — Commercial private beta

## Target

Months 6–9

## Goal

Onboard non-IITM organizations without customer-specific code.

## Deliverables

- Multi-tenant isolation hardening.
- Standard GitHub onboarding.
- Organization identity configuration.
- Customer model-processing settings.
- Data retention and deletion.
- Usage and billing records.
- Quotas.
- Feature flags.
- Customer support tooling.
- Security and privacy documentation.
- Commercial onboarding playbook.

## Exit criteria

- At least three design customers onboard.
- Tenants cannot access one another.
- One organization can be deleted according to policy.
- Usage and cost are attributable.
- Standard onboarding completes within target.
- Customers repeat use weekly.

# Milestone 8 — Broader engineering Anva

## Target

Months 9–12

## Goal

Expand only from demonstrated demand.

Candidate deliverables:

- additional source connectors;
- incident linkage;
- deployment-readiness assurance;
- release assurance;
- cross-repository impact;
- scenario planning;
- additional coding-agent hosts;
- customer-hosted MCP or workers.

Each candidate requires:

- customer evidence;
- explicit success metric;
- architecture decision;
- updated threat model;
- acceptance criteria.

---

# 28. Detailed Initial Backlog

The following issue identifiers should be used for implementation.

## 28.1 Foundation

- `FND-001` Create monorepo structure and build commands.
- `FND-002` Bootstrap Django, PostgreSQL, pgvector, and test settings.
- `FND-003` Bootstrap Next.js and generated API client.
- `FND-004` Add local development environment.
- `FND-005` Add CI for format, lint, type check, unit, integration, and e2e.
- `FND-006` Add OpenTelemetry and structured logging.
- `FND-007` Add transactional outbox foundation.
- `FND-008` Add JSON Schema and OpenAPI generation.
- `FND-009` Create ADR, runbook, and threat-model templates.
- `FND-010` Create synthetic reference organization fixtures.
- `FND-011` Create reference repositories and pull-request fixtures.
- `FND-012` Add fake reasoning evaluator.

## 28.2 Identity and tenancy

- `IAM-001` Organization model.
- `IAM-002` User and external identity model.
- `IAM-003` Membership and role model.
- `IAM-004` Team and team-membership model.
- `IAM-005` Repository-scoped authorization.
- `IAM-006` Entity and source access scopes.
- `IAM-007` Service identity and token model.
- `IAM-008` Authorization decision service.
- `IAM-009` Audit actor resolution.
- `IAM-010` Cross-tenant test suite.
- `IAM-011` Derived-assertion access propagation.
- `IAM-012` Retention-aware user and organization deletion.

## 28.3 GitHub

- `GIT-001` GitHub App manifest and installation flow.
- `GIT-002` Webhook signature validation.
- `GIT-003` Webhook idempotency store.
- `GIT-004` Installation and repository synchronization.
- `GIT-005` Repository metadata client.
- `GIT-006` Issue and work-item ingestion.
- `GIT-007` Pull-request revision ingestion.
- `GIT-008` Diff fetch and immutable artifact.
- `GIT-009` Check and workflow status ingestion.
- `GIT-010` GitHub Check publication.
- `GIT-011` Report marker and update behavior.
- `GIT-012` Finding annotation publication.
- `GIT-013` Merge handling.
- `GIT-014` Installation revocation.
- `GIT-015` Fork security tests.
- `GIT-016` GitHub API rate-limit handling.

## 28.4 Anva entities and ontology

- `BRN-001` KnowledgeEntity identity and type registry.
- `BRN-002` Core organizational entity details.
- `BRN-003` Core engineering entity details.
- `BRN-004` Relationship-type registry.
- `BRN-005` Relationship validation.
- `BRN-006` KnowledgeAssertion model.
- `BRN-007` Assertion revision model.
- `BRN-008` Assertion source and provenance.
- `BRN-009` Assertion review.
- `BRN-010` Conflict representation.
- `BRN-011` Staleness calculation.
- `BRN-012` Correction proposal workflow.
- `BRN-013` Entity merge workflow.
- `BRN-014` Entity split workflow.
- `BRN-015` Temporal entity and relationship query.
- `BRN-016` Entity and relationship APIs.
- `BRN-017` Knowledge audit timeline.
- `BRN-018` Ontology migration/version mechanism.

## 28.5 Source ingestion

- `SRC-001` SourceConnection and SourceContainer models.
- `SRC-002` SourceDocument and SourceRevision models.
- `SRC-003` AccessSnapshot model.
- `SRC-004` SyncRun state machine.
- `SRC-005` Repository-document connector.
- `SRC-006` Selected external document connector.
- `SRC-007` Parser interface and plain Markdown parser.
- `SRC-008` Additional required document parsers.
- `SRC-009` Chunking and indexing.
- `SRC-010` Embedding provider interface.
- `SRC-011` Candidate entity extraction.
- `SRC-012` Entity resolution.
- `SRC-013` Candidate assertion extraction.
- `SRC-014` Assertion publication policy.
- `SRC-015` Conflict detection.
- `SRC-016` Incremental sync and cursors.
- `SRC-017` Source health API and UI.
- `SRC-018` Revocation and deletion propagation.
- `SRC-019` Ingestion evaluation fixtures.
- `SRC-020` Connector threat-model tests.

## 28.6 Repository onboarding

- `ONB-001` Repository scanner.
- `ONB-002` Purpose and ownership proposal.
- `ONB-003` Runtime and framework detection.
- `ONB-004` Command detection.
- `ONB-005` CI check detection.
- `ONB-006` Test and browser-test detection.
- `ONB-007` Sensitive-path proposal.
- `ONB-008` RepositoryProfile model and versioning.
- `ONB-009` Repository profile editor.
- `ONB-010` Technical-owner confirmation.
- `ONB-011` Profile validation without hosted code execution.
- `ONB-012` Onboarding progress and diagnostics.

## 28.7 Search, query, and context

- `CTX-001` Structured entity search.
- `CTX-002` Full-text source search.
- `CTX-003` Semantic source search.
- `CTX-004` Permission filtering before ranking.
- `CTX-005` Context request schema.
- `CTX-006` Phase-specific retrieval.
- `CTX-007` Context budget and deduplication.
- `CTX-008` Context packet persistence and hashing.
- `CTX-009` Context item selection explanations.
- `CTX-010` Context packet API.
- `CTX-011` Assertion explanation API.
- `CTX-012` Natural-language query orchestration.
- `CTX-013` Grounded answer rendering.
- `CTX-014` Retrieval evaluation runner.
- `CTX-015` Retrieval quality dashboard.
- `CTX-016` Context invalidation after correction.

## 28.8 MCP

- `MCP-001` MCP gateway service.
- `MCP-002` MCP capability/version discovery.
- `MCP-003` OAuth authorization flow.
- `MCP-004` Repository and organization scope mapping.
- `MCP-005` Read tool schemas.
- `MCP-006` Proposal tool schemas.
- `MCP-007` Resource URI implementation.
- `MCP-008` Tool-call audit.
- `MCP-009` Output bounding and pagination.
- `MCP-010` Read-only deployment mode.
- `MCP-011` Revocation behavior.
- `MCP-012` MCP contract and security tests.
- `MCP-013` Headless service-identity flow.
- `MCP-014` MCP installation diagnostics.

## 28.9 Developer skills

- `SKL-001` Define host-neutral workflow contracts.
- `SKL-002` Implement `anva-prepare`.
- `SKL-003` Implement `anva-build`.
- `SKL-004` Implement `anva-preflight`.
- `SKL-005` Implement `anva-learn`.
- `SKL-006` Create shared output schemas.
- `SKL-007` Create Codex skill adapter.
- `SKL-008` Create Codex plugin package.
- `SKL-009` Create Claude Code skill adapter.
- `SKL-010` Create Claude Code distribution package.
- `SKL-011` Implement installer and authentication handoff.
- `SKL-012` Implement diagnostics.
- `SKL-013` Implement skill version compatibility.
- `SKL-014` Create Codex host evaluation runner.
- `SKL-015` Create Claude Code host evaluation runner.
- `SKL-016` Add skill security tests.
- `SKL-017` Document organization-managed installation.
- `SKL-018` Add signed/checksummed releases.

## 28.10 Work items and requirements

- `WRK-001` WorkItem and revision model.
- `WRK-002` Requirement and non-requirement models.
- `WRK-003` Assumption model.
- `WRK-004` AcceptanceCriterion model.
- `WRK-005` Requirement source mapping.
- `WRK-006` Requirement-to-entity relationships.
- `WRK-007` Plan and decision model.
- `WRK-008` Approval model.
- `WRK-009` GitHub issue linking.
- `WRK-010` Structured work-summary ingestion.
- `WRK-011` Requirement detail UI.
- `WRK-012` Requirement version and approval guards.

## 28.11 Policies

- `POL-001` Policy model and versioning.
- `POL-002` Policy schema validation.
- `POL-003` Policy binding.
- `POL-004` Path and entity match engine.
- `POL-005` Required-check output.
- `POL-006` Required-evidence output.
- `POL-007` Required-reviewer output.
- `POL-008` Blocking and advisory evaluation.
- `POL-009` Policy explanation.
- `POL-010` Override authorization and audit.
- `POL-011` Historical simulation.
- `POL-012` Policy editor.
- `POL-013` Policy evaluation test corpus.

## 28.12 Evidence

- `EVD-001` Evidence model.
- `EVD-002` Evidence artifact metadata.
- `EVD-003` CriterionEvidence mapping.
- `EVD-004` Existing GitHub Check evidence adapter.
- `EVD-005` Evidence manifest schema.
- `EVD-006` Anva Evidence Action.
- `EVD-007` Signed upload authorization.
- `EVD-008` Artifact validation and scanning.
- `EVD-009` Artifact access and signed URLs.
- `EVD-010` Evidence retention.
- `EVD-011` Evidence upload contract tests.
- `EVD-012` Secret-redaction tests.

## 28.13 Pull-request assurance

- `ASR-001` PullRequestRecord and revision model.
- `ASR-002` AssuranceRun state machine.
- `ASR-003` Trigger debouncing.
- `ASR-004` Pull-request work-item resolution.
- `ASR-005` Deterministic repository-state evaluation.
- `ASR-006` Policy evaluation orchestration.
- `ASR-007` Assurance context packet.
- `ASR-008` ReasoningEvaluator interface.
- `ASR-009` Initial structured evaluator.
- `ASR-010` Diff classification and chunking.
- `ASR-011` Requirement coverage evaluation.
- `ASR-012` Architecture and dependency evaluation.
- `ASR-013` Test and documentation evaluation.
- `ASR-014` Finding model and fingerprint.
- `ASR-015` Finding lifecycle.
- `ASR-016` Readiness calculation.
- `ASR-017` Assurance report renderer.
- `ASR-018` Re-evaluation and stale-run handling.
- `ASR-019` Finding dismissal and accepted-risk flow.
- `ASR-020` Human-review focus generation.
- `ASR-021` Usage and cost recording.
- `ASR-022` Assurance evaluation runner.
- `ASR-023` False-positive feedback loop.
- `ASR-024` Large pull-request limitations.
- `ASR-025` Post-merge learning orchestration.

## 28.14 Organizational Canvas

- `CAN-001` CanvasView and revision models.
- `CAN-002` Node placement and grouping.
- `CAN-003` Typed neighborhood query.
- `CAN-004` Permission-safe path query.
- `CAN-005` Graph rendering prototype and library decision.
- `CAN-006` Canvas shell with pan, zoom, and selection.
- `CAN-007` Node detail panel.
- `CAN-008` Filters and layers.
- `CAN-009` Strategy view.
- `CAN-010` Product and system view.
- `CAN-011` Initiative view.
- `CAN-012` Risk and policy view.
- `CAN-013` Provenance and freshness overlay.
- `CAN-014` Time comparison.
- `CAN-015` Saved views and sharing.
- `CAN-016` Relationship proposal interaction.
- `CAN-017` Selection-scoped Anva query.
- `CAN-018` Accessible list and table alternative.
- `CAN-019` Canvas performance test.
- `CAN-020` Graph-hairball usability test.

## 28.15 Web application

- `WEB-001` Product shell and navigation.
- `WEB-002` Organization setup.
- `WEB-003` Onboarding progress.
- `WEB-004` Attention-oriented home.
- `WEB-005` Anva Explorer.
- `WEB-006` Entity detail.
- `WEB-007` Knowledge review inbox.
- `WEB-008` Repository page.
- `WEB-009` Pull-request assurance detail.
- `WEB-010` Policy list and editor.
- `WEB-011` Skill setup and diagnostics.
- `WEB-012` Source health.
- `WEB-013` Audit search.
- `WEB-014` Loading, empty, error, and stale states.
- `WEB-015` Accessibility regression suite.

## 28.16 Security and privacy

- `SEC-001` Product threat model.
- `SEC-002` Source connector threat-model template.
- `SEC-003` Prompt-injection test corpus.
- `SEC-004` Secret redaction.
- `SEC-005` Model data-governance configuration.
- `SEC-006` Retention policy.
- `SEC-007` Organization deletion.
- `SEC-008` Source-derived deletion.
- `SEC-009` Skill supply-chain checks.
- `SEC-010` Artifact security.
- `SEC-011` OAuth and token revocation tests.
- `SEC-012` External penetration test before commercial beta.
- `SEC-013` Security incident runbook.

## 28.17 Operations and commercial readiness

- `OPS-001` Production Terraform.
- `OPS-002` Backup and restore.
- `OPS-003` Operational dashboards.
- `OPS-004` Alerting.
- `OPS-005` Cost accounting.
- `OPS-006` Organization quotas.
- `OPS-007` Feature flags.
- `OPS-008` Support tooling.
- `OPS-009` Pilot metrics.
- `OPS-010` Usage records.
- `OPS-011` Billing export.
- `OPS-012` Status and incident communication.
- `OPS-013` Data-processing and retention documentation.

## 28.18 Milestone 1 vertical slice

These issues deliberately implement the thinnest useful cross-product path.
They should establish durable seams and schemas, then defer production depth to
the domain backlogs above.

- `VSL-001` Add minimum organization, user, and repository records.
- `VSL-002` Add a manually seeded Anva entity, relationship, and source fixture.
- `VSL-003` Add one versioned requirement, criterion, decision, and policy.
- `VSL-004` Add a minimal context-packet endpoint with stored provenance.
- `VSL-005` Expose one authenticated read-only context tool through MCP.
- `VSL-006` Package one prepare/preflight workflow for Codex and Claude Code.
- `VSL-007` Ingest a test pull request and its existing GitHub Check state.
- `VSL-008` Run the fake evaluator and publish one Anva GitHub Check/report.
- `VSL-009` Create one post-merge knowledge-update proposal.
- `VSL-010` Show the seeded entities and relationships in a minimal web view.

---

# 29. Critical Implementation Path

## 29.1 First vertical slice dependency order

```text
FND-001..012
    ↓
VSL-001..010
```

Use manually seeded entities and deliberately thin implementations for this
slice. Do not block it on automated source extraction or prematurely complete
the full production backlogs.

## 29.2 Trustworthy ingestion path

```text
SRC-001..010
    ↓
SRC-011..015
    ↓
BRN-010..018
    ↓
SRC-016..020
    ↓
CTX-001..004, CTX-011..016
```

## 29.3 Canvas path

```text
BRN-016
    ↓
CAN-001..005
    ↓
CAN-006..013
    ↓
CAN-014..020
```

## 29.4 What must not block the first pilot

- General-purpose ontology customization.
- Multiple document connectors.
- Automatic extraction of every entity type.
- Deployment assurance.
- A graph database.
- Managed customer-code execution.
- Billing.
- Advanced scenario simulation.
- Organization-wide analytics.

---

# 30. Definition of Done

An issue is complete only when all applicable requirements below are satisfied.

## 30.1 Product

- Acceptance criteria are met.
- User-visible behavior matches the approved specification.
- Failure, empty, loading, and stale states are usable.
- Scope remains within the active milestone.
- Product wording does not overclaim assurance.

## 30.2 Anva quality

- New assertions retain provenance.
- Inference is labeled.
- Access scope is correct.
- Revision and staleness behavior are defined.
- Correction behavior is available where relevant.

## 30.3 Code

- Implementation is understandable.
- Domain logic is outside views and integration callbacks.
- External inputs are validated.
- Retried effects are idempotent.
- Critical invariants use database constraints where possible.
- Type checks, lint, and formatting pass.
- Migrations are reviewed.

## 30.4 Tests

- Business logic has unit tests.
- Persistence and external boundaries have integration tests.
- Authorization is tested.
- Failure and retry paths are tested.
- External contracts are tested.
- Browser-visible behavior has end-to-end coverage.
- Model behavior has an evaluation scenario.
- No unrelated test or eval was weakened.

## 30.5 Security

- No secret is logged or packaged.
- Least privilege is preserved.
- Access scope is tested.
- Prompt-injection impact is considered.
- Retention and deletion implications are considered.
- New permissions or data flows are documented.

## 30.6 Documentation

- API and MCP schemas are updated.
- User-facing setup is updated.
- Relevant runbook is updated.
- ADR exists for architectural decisions.
- Product roadmap status is updated.
- Compatibility and migration notes exist where required.

## 30.7 Evidence

- Commands and results are recorded in the issue or completion report.
- Evaluation results are linked.
- Known limitations are explicit.
- Acceptance criteria map to implementation evidence.

---

# 31. Coding and Design Standards

## 31.1 General

- Prefer explicit code and schemas.
- Keep functions purpose-specific.
- Use type annotations.
- Validate every external input.
- Use structured errors.
- Do not catch broad exceptions without recording context and preserving failure.
- Put side effects behind small interfaces.
- Make retries idempotent.
- Document invariants.
- Use migrations for schema changes.
- Keep tenant identity explicit.

## 31.2 Backend

- Service-layer functions own domain operations.
- Views and webhook handlers remain thin.
- State transitions occur through authoritative services.
- Background jobs receive identifiers.
- External writes use the outbox.
- Authorization is checked inside the domain operation, not only in the UI.
- Timestamps use UTC.
- Transaction boundaries are intentional.
- Query counts and recursive traversals are bounded.

## 31.3 Frontend

- Generate API types.
- Do not infer authorization from hidden buttons.
- Represent source freshness and assurance staleness.
- Keep destructive actions explicit.
- Preserve deep links.
- Use semantic HTML.
- Provide keyboard and screen-reader paths.
- Keep large lists and graph views efficient.

## 31.4 Skills

- Keep descriptions precise enough for reliable triggering.
- Keep the main workflow concise.
- Load detailed references only when needed.
- Declare dependencies.
- Avoid embedding customer facts.
- Avoid opaque executable scripts.
- Make write operations explicit.
- Never claim server-side readiness.
- Test each supported host.

## 31.5 Model prompts

- Version prompts.
- Require structured output.
- Separate instructions from untrusted content.
- Require citations.
- Include explicit unknown and limitation fields.
- Do not ask the model to make authorization decisions.
- Run evaluation gates before changes.

## 31.6 Reports

- Deterministic from stored data.
- Testable with golden files.
- Never claim a check passed without evidence.
- Never hide limitations.
- Keep blocking and advisory findings separate.
- Prefer concise, review-focused language.

---

# 32. Architecture Decision Records

Create the following ADRs as relevant work begins:

- `ADR-001` V2 product boundary: Anva, skills, and PR assurance.
- `ADR-002` Monorepo structure.
- `ADR-003` PostgreSQL hybrid knowledge storage.
- `ADR-004` Knowledge entity, assertion, and relationship model.
- `ADR-005` Temporal provenance and review model.
- `ADR-006` GitHub-first engineering integration.
- `ADR-007` Remote MCP as live agent context interface.
- `ADR-008` Portable skill source with host-specific packaging.
- `ADR-009` Codex plugin distribution.
- `ADR-010` Claude Code skill distribution.
- `ADR-011` Existing CI consumption rather than hosted execution.
- `ADR-012` Evidence and readiness model.
- `ADR-013` Stateless structured reasoning evaluator.
- `ADR-014` Canvas as projection rather than canonical graph.
- `ADR-015` Permission propagation for derived assertions.
- `ADR-016` Transactional outbox and background dispatch.
- `ADR-017` Initial external document connector.
- `ADR-018` Model-processing and retention policy.
- `ADR-019` Open-source and hosted boundary.
- `ADR-020` Multi-tenant isolation.

Each ADR must contain:

```text
Context
Decision
Alternatives considered
Consequences
Security impact
Privacy impact
Operational impact
Revisit conditions
```

---

# 33. Risks and Mitigations

## 33.1 Scope expands back into an agent harness

Risk:

Customers request Anva to run coding agents because it already supplies context
and evaluates pull requests.

Mitigation:

- enforce the product boundary;
- integrate with existing agents through skills and MCP;
- require customer evidence before hosted execution;
- treat managed execution as a separate later product decision.

## 33.2 Anva becomes a stale knowledge graveyard

Risk:

Ingested content accumulates while reality changes.

Mitigation:

- freshness state;
- source sync;
- conflict detection;
- post-merge proposals;
- high-impact review queue;
- retrieval penalties for stale claims;
- correction feedback loop.

## 33.3 Graph looks impressive but does not help decisions

Risk:

The Canvas becomes a visually attractive graph with low operational value.

Mitigation:

- purpose-built views;
- start from management and technical-owner questions;
- connect nodes to active work and action;
- measure completed jobs, not graph interaction;
- avoid rendering the full graph.

## 33.4 Skills are mistaken for enforcement

Risk:

Customers assume installing a skill guarantees compliance.

Mitigation:

- explicitly label local preflight advisory;
- enforce only at server-side GitHub Check and policy boundaries;
- keep independent evaluation;
- show whether a PR used Anva context without treating that as proof of quality.

## 33.5 Skill behavior differs across hosts

Risk:

The same workflow triggers or behaves differently in Codex and Claude Code.

Mitigation:

- portable conceptual specification;
- thin host adapters;
- host-specific evals;
- version compatibility;
- avoid promising byte-identical behavior.

## 33.6 Context leaks across permissions

Risk:

Derived assertions, search, Canvas paths, or model prompts reveal restricted
information.

Mitigation:

- access filtering before retrieval;
- derived access scopes;
- permission-safe traversal;
- cross-tenant and cross-source tests;
- minimal context;
- security review.

## 33.7 Reviewers ignore AI reports

Risk:

Reports are verbose, repetitive, or wrong.

Mitigation:

- concise readiness summary;
- evidence and sources;
- deterministic/model separation;
- false-positive feedback;
- stable finding fingerprints;
- focus on human-review priorities.

## 33.8 Generic code-review market pressure

Risk:

Customers compare Anva with generic pull-request review tools.

Mitigation:

- lead with organizational context;
- connect strategy, systems, decisions, and code;
- provide management Canvas;
- demonstrate better organization-specific findings and requirement traceability;
- make generic lint-like findings secondary.

## 33.9 Integrations consume the roadmap

Risk:

Every customer requests different sources.

Mitigation:

- GitHub plus one document source initially;
- connector interface;
- customer-value threshold for new connectors;
- allow manual links and imports;
- price or partner for long-tail integrations later.

## 33.10 Extraction quality is poor

Risk:

Anva creates duplicate, incorrect, or overconfident entities.

Mitigation:

- mechanical facts first;
- confidence and inference labels;
- high-impact review;
- entity-resolution queue;
- corrections;
- extraction evals;
- do not block assurance on unreviewed interpretive assertions.

## 33.11 Model and inference cost

Risk:

Source ingestion and PR analysis become uneconomic.

Mitigation:

- incremental sync;
- content hashing;
- reuse unchanged extraction;
- deterministic filtering;
- bounded context;
- model tiers by task;
- per-organization budgets;
- cost per useful PR metric.

## 33.12 "Anva" creates surveillance concerns

Risk:

Employees perceive the product as centralized monitoring.

Mitigation:

- transparent data and access;
- no individual scoring;
- context and system health over activity tracking;
- visible corrections;
- clear customer governance;
- consider a less controlling market name.

## 33.13 "Production-ready" overclaim

Risk:

Customers treat a readiness status as a deployment warranty.

Mitigation:

- define readiness precisely;
- use `READY_FOR_HUMAN_REVIEW`;
- list unverified areas;
- no `SAFE_TO_DEPLOY` in MVP;
- contractual and UI wording review.

## 33.14 GitHub or agent-host surface changes

Risk:

Codex, Claude Code, or GitHub changes extension or integration behavior.

Mitigation:

- host adapters;
- contract tests;
- capability discovery;
- version support policy;
- use open protocols and skill formats where practical;
- verify official documentation before releases.

## 33.15 Human review burden

Risk:

Knowledge review creates another inbox no one maintains.

Mitigation:

- prioritize high-impact uncertainty;
- auto-accept mechanical facts;
- assign domain ownership;
- batch review;
- measure unused proposals;
- expire low-value items.

---

# 34. Open Product Decisions

These decisions should be resolved before or during Milestone 0.

## 34.1 Initial document source

Candidates should be evaluated against IITM's actual workflow.

Selection criteria:

- contains meaningful product and architecture context;
- permission model can be respected;
- API and change events are viable;
- source links are stable;
- onboarding is acceptable.

Decision owner: Founder with IITM technical owner.

## 34.2 Requirement authority

Question:

Will initial requirements be Anva-native records, normalized GitHub issue
content, or both?

Recommendation:

Use GitHub as the collaboration surface and Anva as the versioned normalized
requirement and evidence model.

## 34.3 Plan approval in MVP

Question:

Must every pull request have an explicitly approved Anva plan?

Recommendation:

Require explicit approval only for configured work classes initially. Permit
assurance without an approved plan but show a requirement-traceability gap.

## 34.4 Initial evaluator provider

Choose based on:

- structured output reliability;
- privacy and retention requirements;
- context handling;
- cost;
- latency;
- evaluation quality.

The product schema must remain provider-neutral.

## 34.5 Skill distribution

Question:

Should the first pilot check skills into each repository or install them through
organization/user distribution?

Recommendation:

Support repository-local installation first for transparency and repeatability,
then add organization-managed distribution for scale. Package Codex as a plugin
once the MCP connection and workflows stabilize.

## 34.6 Canvas edit authority

Question:

Who may propose or approve relationships created visually?

Recommendation:

Any authorized member may propose. Domain owners or knowledge admins approve
high-impact relationship types.

## 34.7 Public versus private Anva MCP

Question:

Should the MCP service be reachable as a hosted public endpoint with OAuth, or
initially restricted to a design-partner network?

Recommendation:

Use hosted HTTPS with OAuth for the pilot if IITM policy permits. Preserve a
future private-network deployment option.

## 34.8 Open-source boundary

Candidate open components:

- skill workflows;
- context packet schema;
- evidence manifest schema;
- policy format;
- MCP tool schemas;
- repository profile;
- local evidence uploader.

Hosted differentiation:

- continuous Anva synchronization;
- permissions;
- organizational model;
- assurance service;
- Canvas;
- audit;
- multi-tenancy;
- retention;
- support.

Defer the final boundary until the private pilot demonstrates which pieces drive
adoption and retention.

## 34.9 Product name

"Anva" remains a working name.

Naming criteria:

- ownable;
- trustworthy;
- not surveillance-oriented;
- communicates context and organizational memory;
- broad enough for later domains;
- precise enough to be understood.

Naming is not a Milestone 0 blocker.

---

# 35. V1 to V2 Scope Mapping

## 35.1 Preserved as core

| V1 capability | V2 treatment |
|---|---|
| Organizational knowledge | Promoted to the primary product |
| Knowledge provenance | Preserved and expanded |
| Requirements | Preserved |
| Acceptance criteria | Preserved |
| Policy engine | Preserved |
| Evidence model | Preserved |
| Independent verification | Reframed as PR Assurance |
| GitHub integration | Preserved |
| Audit history | Preserved |
| Post-merge updates | Preserved |
| Human approval | Preserved where consequential |
| Repository onboarding | Preserved without hosted boot execution |

## 35.2 Replaced

| V1 capability | V2 replacement |
|---|---|
| Agent-provider execution interface | Developer-owned Codex/Claude skills |
| Agent context injection by orchestrator | Authenticated Anva MCP context |
| Implement workflow run by Anva | `anva-build` skill in existing agent |
| Hosted implementation checkpoints | Developer tool and Git history |
| Draft PR creation | Developer's existing agent or workflow |
| Verification sandbox | Existing customer CI evidence |

## 35.3 Deferred

| V1 capability | Reason |
|---|---|
| Per-task Compute Engine VM | Anva does not execute customer code |
| Sandbox controller/runtime | Outside product boundary |
| Hosted browser reproduction | High infrastructure and scope cost |
| Coding-agent provider routing | Developers already choose their agent |
| Automatic implementation | Not required for Anva value |
| Resumable provider sessions | Owned by agent host |
| Multi-repository autonomous implementation | Later, if ever |

## 35.4 Removed from initial positioning

- Engineering agentic control plane.
- Give the platform an issue and receive an implemented PR.
- CI/CD replacement implications.
- Autonomous coding workflow ownership.

## 35.5 New primary positioning

> Anva gives coding agents the organizational context to build the right
> change, then independently verifies the pull request against requirements,
> policy, systems, and evidence.

---

# 36. Immediate Next Steps

1. Review and annotate this v3 document.
2. Resolve the open decisions required for Milestone 0.
3. Preserve the v1 document as historical rationale.
4. Mark this file canonical after founder approval.
5. Create `ADR-001` for the v3 product boundary.
6. Create Milestone 0 issues `FND-001` through `FND-012`.
7. Select one reference repository and one synthetic reference organization.
8. Select one real IITM repository for the first shadow pilot.
9. Implement the Milestone 1 thin vertical slice before broad automated
   ingestion.
10. Do not build hosted agent execution, customer-code sandboxes, or deployment
    automation during the initial milestones.

---

# 37. Suggested First Implementation Instruction

```text
Read anva-product-requirements-and-implementation-plan-v3.md completely.

Implement Milestone 0 only.

Scope:
- FND-001 through FND-012.

Before editing:
1. inspect the repository;
2. restate the Milestone 0 exit criteria;
3. identify missing toolchain requirements;
4. propose the monorepo structure and test plan;
5. identify decisions that require founder approval.

Requirements:
- create the reproducible monorepo foundation;
- bootstrap Django, PostgreSQL with pgvector, and Next.js;
- create schema and generated-client foundations;
- add CI and local development;
- create ADR, runbook, and threat-model templates;
- create a synthetic reference-organization fixture;
- create a small reference repository fixture;
- create a deterministic fake reasoning evaluator;
- do not implement GitHub, MCP, real model calls, source ingestion, skills,
  assurance, or Canvas behavior yet;
- do not introduce an agent runtime, workflow engine, graph database, or
  customer-code sandbox.

After editing:
- run all available checks;
- provide an end-of-task report containing completed requirements, files
  changed, tests added, commands run, results, security considerations,
  deviations, limitations, and follow-up issues.
```

---

# 38. Final Product Direction

The product should evolve in this order:

```text
Trusted sources
→ entities and assertions
→ provenance and permissions
→ bounded context
→ developer skills
→ pull-request assurance
→ evidence and policy
→ post-merge learning
→ Organizational Canvas
→ broader engineering workflows
→ broader organizational domains
```

The primary product objective is:

> Make Anva the trusted organizational context layer used by humans and agents
> to understand, change, and improve the organization.

The initial engineering objective is:

> Help developers produce review-ready, organization-aware pull requests using
> the coding agents they already prefer.

The initial business objective is:

> Establish Anva through a narrow, high-frequency engineering workflow, then
> expand from a trusted system of context into the visual and operational model
> of the organization.

---

# Appendix A — Canonical Product Messages

## Short

> Anva is the organizational context layer for humans and coding agents.

## Developer

> Give Codex or Claude the context to build for your organization, then verify
> every pull request independently.

## Engineering leader

> Connect strategy, teams, systems, decisions, and code in one living,
> source-backed model.

## Pull-request assurance

> Make the first pull request ready for serious human review—with requirements,
> policy, organizational context, and evidence attached.

## Avoid

- "Anva guarantees bug-free code."
- "Anva replaces your CI/CD."
- "Anva supervises your developers."
- "Anva autonomously runs your engineering organization."
- "Anva makes every pull request safe to deploy."

---

# Appendix B — Context Packet Example

```json
{
  "packet_id": "ctx_iitm_exam_reschedule_v3",
  "context_version": "sha256:cc1d...",
  "generated_at": "2026-07-28T10:30:00Z",
  "phase": "BUILD",
  "organization": {
    "id": "org_iitm",
    "name": "IIT Madras"
  },
  "actor": {
    "id": "usr_42",
    "authorization_snapshot": "acl_884"
  },
  "repository": {
    "id": "repo_exam_platform",
    "default_branch": "main",
    "owners": ["team_exam_platform"]
  },
  "task": {
    "id": "work_452",
    "title": "Allow authorized exam rescheduling",
    "source": "https://github.example/issues/452"
  },
  "requirements": [
    {
      "id": "req_1",
      "text": "Authorized administrators can reschedule an unpublished exam.",
      "source_ids": ["src_issue_452"],
      "status": "APPROVED"
    }
  ],
  "acceptance_criteria": [
    {
      "id": "ac_1",
      "text": "A rescheduled exam displays the new start and end time.",
      "required_evidence": ["TEST_RESULT", "SCREENSHOT"]
    }
  ],
  "affected_entities": [
    {
      "id": "svc_exam_scheduler",
      "type": "Service",
      "relationship": "LIKELY_CHANGED",
      "confidence": 0.92,
      "sources": ["src_architecture_17"]
    }
  ],
  "policies": [
    {
      "id": "policy_time_change_audit",
      "version": 2,
      "severity": "blocking",
      "requirements": ["audit-log-test"]
    }
  ],
  "decisions": [
    {
      "id": "adr_28",
      "summary": "Store all exam times in UTC.",
      "status": "HUMAN_CONFIRMED",
      "source": "https://docs.example/adr-28"
    }
  ],
  "unresolved_conflicts": [],
  "limitations": [
    "The staging deployment procedure was last verified 120 days ago."
  ]
}
```

---

# Appendix C — Finding Example

```json
{
  "finding_id": "finding_123",
  "fingerprint": "sha256:...",
  "kind": "REQUIREMENT_GAP",
  "severity": "BLOCKING",
  "confidence": "HIGH_CONFIDENCE",
  "title": "Authorization requirement is not enforced",
  "explanation": "The new endpoint changes the exam schedule without checking the administrator permission required by REQ-1.",
  "location": {
    "path": "apps/exams/views.py",
    "line": 184,
    "commit_sha": "abc123"
  },
  "requirements": ["req_1"],
  "policies": ["policy_admin_actions"],
  "evidence": [
    {
      "type": "DIFF_REFERENCE",
      "reference": "diff_123:apps/exams/views.py:184"
    }
  ],
  "brain_sources": [
    {
      "assertion_id": "assertion_admin_permission",
      "source_url": "https://docs.example/exam-permissions"
    }
  ],
  "uncertainty": "The repository may enforce this permission in middleware not included in the changed call path; a human should confirm if such middleware applies."
}
```

---

# Appendix D — Skill Contract

Every Anva skill should:

1. Identify the organization and repository.
2. Identify or request the work item.
3. Request the minimum relevant context packet.
4. Display material source, freshness, and conflict limitations.
5. Separate facts, requirements, assumptions, and suggestions.
6. Keep implementation within approved scope.
7. Run or recommend repository checks appropriate to the phase.
8. Produce structured output.
9. Offer explicit knowledge proposals.
10. Never represent local preflight as authoritative PR assurance.

Every Anva skill must fail safely when:

- authentication is unavailable;
- the organization is unresolved;
- the repository is not onboarded;
- context access is denied;
- the MCP contract version is unsupported;
- Anva reports a material knowledge conflict;
- write approval is declined.

---

# Appendix E — Production Readiness Checklist

## Control plane

- [ ] Database backups configured and restored in a drill.
- [ ] Migrations rehearsed.
- [ ] Audit enabled.
- [ ] Error tracking configured.
- [ ] Traces configured.
- [ ] Rate limits configured.
- [ ] Authentication configured.
- [ ] Authorization reviewed.

## Anva

- [ ] Source provenance tested.
- [ ] Source revocation tested.
- [ ] Assertion review tested.
- [ ] Conflict behavior tested.
- [ ] Staleness tested.
- [ ] Derived access scope tested.
- [ ] Context reconstruction tested.

## GitHub

- [ ] App permissions reviewed.
- [ ] Webhook signatures verified.
- [ ] Duplicate delivery tested.
- [ ] Installation revocation tested.
- [ ] Check publication tested.
- [ ] Fork behavior tested.

## MCP and skills

- [ ] OAuth tested.
- [ ] Revocation tested.
- [ ] Read-only mode tested.
- [ ] Tool schemas pinned.
- [ ] Codex package tested.
- [ ] Claude Code package tested.
- [ ] Skill integrity verified.
- [ ] Host compatibility documented.

## Assurance

- [ ] Deterministic checks tied to commit.
- [ ] Policy versions stored.
- [ ] Evidence mapping tested.
- [ ] Findings cite sources.
- [ ] Re-evaluation tested.
- [ ] Stale status tested.
- [ ] False-positive process defined.
- [ ] Model-regression gate active.

## Security and privacy

- [ ] Threat model reviewed.
- [ ] Cross-tenant tests pass.
- [ ] Prompt-injection tests pass.
- [ ] Secret-redaction tests pass.
- [ ] Retention configured.
- [ ] Deletion tested.
- [ ] Model-processing policy documented.
- [ ] Incident process defined.

## Operations

- [ ] Runbooks exist.
- [ ] Alerts exist.
- [ ] Cost dashboard exists.
- [ ] Source health dashboard exists.
- [ ] Support owner identified.
- [ ] IITM escalation contacts identified.

---

# Appendix F — External Integration Assumptions

The extension plan in this document is based on the following verified product
capabilities as of 2026-07-28:

- Codex skills use a `SKILL.md`-based package with optional scripts, references,
  assets, and declared MCP dependencies.
- Codex plugins can package skills and MCP server configuration together.
- Codex supports authenticated remote MCP connections and configurable
  per-tool approval behavior.
- Claude Code supports project and user Agent Skills and remote MCP connections.
- Claude Code plugins may package reusable extension components.

Implementation must revalidate exact packaging, installation, authentication,
and compatibility behavior against current official documentation before each
public release:

- [OpenAI: Build skills](https://developers.openai.com/codex/skills)
- [OpenAI: Package a plugin](https://developers.openai.com/plugins/build/plugins)
- [OpenAI: MCP](https://developers.openai.com/codex/mcp)
- [Anthropic: Claude Code skills](https://code.claude.com/docs/en/slash-commands)
- [Anthropic: Claude Code extension overview](https://code.claude.com/docs/en/features-overview)
- [Anthropic: MCP](https://docs.anthropic.com/en/docs/mcp)

Provider-specific details are adapters, not Anva domain invariants.
