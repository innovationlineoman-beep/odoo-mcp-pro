# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-04-17

### Changed
- **Pricing update**: Pro is now EUR 25/user/month (was EUR 5), Max is EUR 100/user/month (was EUR 25)
- **Plan features unified**: all plans (Free, Pro, Max) now include unlimited connections and team management — daily call limit and priority support (Max only) are the remaining differentiators

## [1.3.0] - 2026-04-16

### Added
- **Billing & subscriptions**: Free, Pro (EUR 25/user/mo), and Max (EUR 100/user/mo) plans with Stripe Checkout and Customer Portal
- **Usage tracking**: daily call counter with progress bar, rate limiting per plan (50 / 500 / 5,000 calls/day)
- **Rate limit upgrade CTA**: when you hit your daily limit, the error message includes a direct link to upgrade
- **Team invites via email**: invite colleagues by email with a branded landing page (powered by Brevo)
- **Multiple connections**: save and switch between Odoo instances without disconnecting Claude
- **Progressive setup validation**: step-by-step connection setup with live URL detection, version check, and auth test
- **Database name help**: guidance for self-hosted users who need to specify a database name
- **Plan badge in sidebar**: always see your current plan and today's usage at a glance

### Changed
- **Teams available on all plans**: teams and unlimited connections are no longer gated behind paid plans
- **Simplified team UI**: removed member/admin role distinction — all team members are equal
- **Billing page redesign**: clean plan comparison cards with current plan highlighting (Vercel-inspired)
- **Setup instructions**: detailed step-by-step Claude connector guide (profile → settings → connectors → add → connect)
- **Invite landing page**: says "sign in or create account" instead of just "sign up"
- **Stripe opens in new tab**: checkout and customer portal open in a new window so you don't lose your place

### Fixed
- **New users get Free plan**: previously new registrations had no plan assigned, breaking rate limiting
- **Billing buttons**: return proper JSON errors for AJAX requests instead of HTML error pages
- **Registration blocked**: removed Zitadel org scope that prevented new users from signing up

## [1.2.1] - 2026-04-11

### Added
- **PostHog auth flow tracking**: server-side events for login success, callback errors, state loss, token exchange failures (privacy-respecting, no PII)
- **PostHog "MCP System Health" dashboard** with alerts for auth failures and usage drops
- **Auth error pages**: clear error messages instead of silent redirect loops on login failures
- **Token introspection caching**: 60-second cache with retry logic reduces Zitadel round-trips
- **CORS handler** on `/admin/callback` (fixes OPTIONS preflight returning 405)
- **Connection profiles**: save multiple Odoo connections and switch instantly without disconnecting Claude

### Changed
- **PKCE state persisted in Postgres**: login state survives blue-green deploys (was in-memory)
- **Deploy drain period**: old container runs 30 seconds after new is healthy (drains in-flight requests)
- **Access token lifetime**: increased to 48 hours (was 12h) since Claude clients don't reliably auto-refresh
- **Refresh tokens enabled**: 90-day lifetime for seamless re-authentication
- **Zitadel email delivery**: custom SMTP via Brevo (fixes "could not verify email" for corporate domains)
- **Setup page redesign**: Vercel-inspired UI with active connection card, inline edit, compact profile list
- **Hardcoded Zitadel fallbacks removed**: ZITADEL_HOST and ZITADEL_ORG_ID are now required env vars

### Fixed
- **Registration broken via claude.ai**: Caddy OAuth proxy pointed to old locked US Zitadel instance
- **Login loops during deploy**: PKCE state lost when container restarted mid-OAuth-flow
- **503 during deploy**: old container removed too early, Caddy had no healthy upstream
- **Caddy DNS errors**: stopped containers kept DNS name, causing intermittent health check failures

## [1.2.0] - 2026-04-05

### Added
- **Admin dashboard** (`/admin/dashboard`): super admin view with all users, usage stats, sort/filter, CSV export
- **Teams**: users sharing the same Odoo instance are automatically grouped into a team
- **Team roles**: first user to connect an Odoo URL becomes team admin; others are members
- **Invite system**: team admins can create invite links (7-day expiry) for colleagues to join their team
- **Team management**: team admins can remove members and revoke pending invites
- **PostHog analytics**: server-side `mcp_tool_called` events (opt-in via `POSTHOG_API_KEY` env var, disabled for self-hosted)
- **Blue-green deploy** (`deploy.sh`): zero-downtime deployments using alternating mcp-blue/mcp-green containers
- **Dev login** (`/admin/login/dev`): instant admin login for local development (requires `ADMIN_DEV_LOGIN=true`)
- **Brand layout** (`brand_base.html`): shared Pantalytics-branded template with sidebar navigation and avatar dropdown
- **`?next=` redirect**: invite links redirect back after login

### Changed
- **Search default limit**: increased from 10 to 100 records (max raised to 500)
- **Setup instructions**: added steps 4-6 explaining the Connect button, sign-in popup, and OAuth approval flow
- **Reconnect tip**: setup page now notes to disconnect/reconnect when changing settings
- **Admin panel layout**: all pages (My Connection, Team, Dashboard) share the sidebar layout with profile dropdown
- **Caddy config**: uses `import mcp_upstream` snippet for DRY upstream definitions
- **Health checks**: Caddy and Docker use `/.well-known/oauth-protected-resource` (not `/mcp` which returns 401)

### Fixed
- **URL normalization**: trailing slashes and paths (`/web`, `/odoo`) are stripped on save for consistent team matching

## [1.0.0] - 2026-03-27

### Added
- **Multi-tenant SaaS architecture**: one MCP server serves multiple customers, each with their own Odoo instance
- **Admin panel** (`/admin`): tenant management and user self-service setup page with Jinja2 + Tailwind
- **OAuth 2.1 via Zitadel Cloud**: token-based authentication for Claude.ai users (PKCE, introspection)
- **Dynamic Client Registration (DCR)**: `/register` endpoint returns pre-configured client_id for Claude.ai
- **ConnectionRegistry**: maps authenticated users to Odoo connections via Postgres (30 min TTL cache)
- **API key encryption**: user Odoo API keys encrypted at rest with Fernet (AES-128)
- **Pantalytics branding**: login page, setup page, admin panel
- **`server_info` tool**: exposes server version and git commit hash
- **Protected Resource Metadata (PRM)**: RFC 9728 discovery pointing to Zitadel as authorization server

### Changed
- **Architecture**: from single-tenant stdio to multi-tenant SaaS with Postgres + Zitadel + Docker
- **Deployment**: Docker Compose on Hetzner VPS with Caddy (TLS) reverse proxy
- **Setup page**: shows all tenants a user belongs to, each with its own API key form
- **`list_models`**: fetches from `ir.model` in JSON/2 mode, skips per-model permission checks for performance
- **Logout**: clears Zitadel session and shows account picker on next login

### Fixed
- **OAuth discovery**: correct PRM routing, issuer URL pointing to server root
- **Caddy proxy**: `/authorize`, `/token`, `/register` routes proxied to Zitadel for Claude.ai compatibility
- **Setup page**: POST handler uses redirect instead of broken template render
- **Tool responses**: use tenant URL instead of placeholder

### Removed
- **YOLO mode**: removed in favor of Odoo native permissions as single source of truth (v0.6.0/v0.7.0)
- **Admin dashboard tenant CRUD**: simplified to self-service setup only
- **V1 login UI references**: use Zitadel Login UI V2 only

## [0.4.0] - 2026-02-22

### Added
- **Structured output**: All tools return typed Pydantic models with auto-generated JSON schemas for MCP clients (`SearchResult`, `RecordResult`, `ModelsResult`, `CreateResult`, `UpdateResult`, `DeleteResult`)
- **Tool annotations**: All tools declare `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` via MCP `ToolAnnotations`
- **Resource annotations**: All resources declare `audience` and `priority` via MCP `Annotations`
- **Human-readable titles**: All tools and resources include `title` for better display in MCP clients

### Changed
- **MCP SDK**: Upgraded from `>=1.9.4` to `>=1.26.0,<2`
- **`get_record` structured output**: Returns `RecordResult` with separate `record` and `metadata` fields instead of injecting `_metadata` into record data
- **Tooling**: Replace black/mypy with ruff format/ty for formatting and type checking

### Fixed
- **VertexAI compatibility**: Simplified `search_records` `domain`/`fields` type hints from `Union` to `Optional[Any]` to avoid `anyOf` JSON schemas rejected by VertexAI/Google ADK (#27)
- **Stale record data**: Removed record-level caching from `read()` to prevent returning stale field values (e.g. `active`) when records change in Odoo between calls (#28)
- **Tests**: Integration tests now use `ODOO_URL` for server detection, deduplicated server checks, fixed async test handling, updated assertions for structured output types, halved suite runtime

### Removed
- Legacy error type aliases (`ToolError`, `ResourceError`, `ResourceNotFoundError`, `ResourcePermissionError`) — use `ValidationError`, `NotFoundError`, `PermissionError` directly
- Unused `_setup_handlers()` method from `OdooMCPServer`

## [0.3.1] - 2026-02-21

### Fixed
- **Authentication bypass**: Add missing `@property` on `is_authenticated` — was always truthy as a method reference, bypassing auth guards

### Changed
- Update CI dependencies (black 26.1.0, GitHub Actions v6/v7)
- Server version test validates semver format instead of hardcoded value

## [0.3.0] - 2025-09-14

### Added
- **YOLO Mode**: Development mode for testing without MCP module installation
  - Read-Only: Safe demo mode with read-only access to all models
  - Full Access: Unrestricted access for development (never use in production)
  - Works with any standard Odoo instance via native XML-RPC endpoints

## [0.2.2] - 2025-08-04

### Added
- **Direct Record URLs**: Added `url` field to `create_record` and `update_record` responses for direct access to records in Odoo

### Changed
- **Minimal Response Fields**: Reduced `create_record` and `update_record` tool responses to return only essential fields (id, name, display_name) to minimize LLM context usage
- **Smart Field Optimization**: Implemented dynamic field importance scoring to reduce smart default fields to most essential across all models, with configurable limit via `ODOO_MCP_MAX_SMART_FIELDS`

## [0.2.1] - 2025-06-28

### Changed
- **Resource Templates**: Updated `list_resource_templates` tool to clarify that query parameters are not supported in FastMCP resources

## [0.2.0] - 2025-06-19

### Added
- **Write Operations**: Enabled full CRUD functionality with `create_record`, `update_record`, and `delete_record` tools (#5)

### Changed
- **Resource Simplification**: Removed query parameters from resource URIs due to FastMCP limitations - use tools for advanced queries (#4)

### Fixed
- **Domain Parameter Parsing**: Fixed `search_records` tool to accept both JSON strings and Python-style domain strings, supporting various format variations

## [0.1.2] - 2025-06-19

### Added
- **Resource Discovery**: Added `list_resource_templates` tool to provide resource URI template information
- **HTTP Transport**: Added streamable-http transport support for web and remote access

## [0.1.1] - 2025-06-16

### Fixed
- **HTTPS Connection**: Fixed SSL/TLS support by using `SafeTransport` for HTTPS URLs instead of regular `Transport`
- **Database Validation**: Skip database existence check when database is explicitly configured, as listing may be restricted for security

## [0.1.0] - 2025-06-08

### Added

#### Core Features
- **MCP Server**: Full Model Context Protocol implementation using FastMCP with stdio transport
- **Dual Authentication**: API key and username/password authentication
- **Resource System**: Complete `odoo://` URI schema with 5 operations (record, search, browse, count, fields)
- **Tools**: `search_records`, `get_record`, `list_models` with smart field selection
- **Auto-Discovery**: Automatic database detection and connection management

#### Data & Performance
- **LLM-Optimized Output**: Hierarchical text formatting for AI consumption
- **Connection Pooling**: Efficient connection reuse with health checks
- **Pagination**: Smart handling of large datasets
- **Caching**: Performance optimization for frequently accessed data
- **Error Handling**: Comprehensive error sanitization and user-friendly messages

#### Security & Access Control
- **Multi-layered Security**: Odoo permissions + MCP-specific access controls
- **Session Management**: Automatic credential injection and session handling
- **Audit Logging**: Complete operation logging for security

## Limitations
- **No Prompts**: Guided workflows not available
- **Alpha Status**: API may change before 1.0.0

**Note**: This alpha release provides production-ready data access for Odoo via AI assistants.