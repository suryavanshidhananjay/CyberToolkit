# AI_PROJECT_CONTEXT

## 1. PROJECT OVERVIEW
- Product: "Instant Insight Tracker" — a lightweight web app to capture, tag, and summarize ideas or tasks with AI-assisted notes.
- Problem: Teams lose momentum during brainstorming; notes scatter across tools, making follow-up slow.
- Target Users: Startup founders, hackathon teams, product squads needing fast capture and organized playback.
- MVP Features: (1) Authenticated workspace, (2) Create/edit notes with tags, (3) Fast search/filter, (4) AI-assisted summary per note, (5) Shareable read-only view for a note.

## 2. PRODUCT VISION
- Long-term: Multi-tenant knowledge hub with real-time collaboration, reminders, rich embeds, and analytics.
- Emphasis: Ship a minimal, reliable demo first; defer advanced collaboration until after hackathon.

## 3. MVP FEATURE LIST
- Auth: Email/password or magic-link via hosted auth (Clerk/Firebase/Supabase) with basic roles (owner, member).
- Notes CRUD: Create, edit, soft delete, restore; required fields: title, body, tags.
- Tagging & Filter: Add/remove tags; filter by tag and text search.
- AI Summary: Button to generate/update a short summary using an LLM API; show loading/error states.
- Shareable Note: Public, read-only link toggled per note.
- Activity Log (light): Per-note history entries for create/update/delete/summarize events.

## 4. TECH STACK (OPTIMIZED FOR HACKATHONS)
- Frontend: React + Vite (fast dev, HMR, minimal boilerplate). Next.js acceptable if SSR/ISR needed, but prefer Vite for speed.
- Backend: Node.js + Express (tiny footprint, huge ecosystem, easy middleware composition). FastAPI is an option if Python needed.
- Database: Supabase (hosted Postgres with auth, storage, RLS) to avoid ops. Plain PostgreSQL OK if managed.
- Auth: Supabase Auth or Clerk for turnkey flows and social login; choose one to avoid custom crypto.
- Styling: TailwindCSS for rapid, consistent UI tokens.
- Deployment: Vercel (frontend) + Supabase (backend/db) or Render/Fly for Express API. Choose the quickest path supported by team accounts.
- AI: Use a hosted LLM API (OpenAI/Groq/Anthropic) behind server routes to keep keys server-side.

## 5. PROJECT STRUCTURE
- /frontend: Vite React app
  - /src/components: Reusable UI pieces (buttons, inputs, layouts, empty states)
  - /src/pages or /src/routes: Page-level views (Dashboard, Note detail, Public view)
  - /src/hooks: Data fetching, auth, feature hooks
  - /src/lib: Client utilities (api client, formatting)
  - /src/styles: Tailwind config, globals
- /backend: Express service
  - /controllers: HTTP handlers mapping requests to services
  - /routes: Route definitions and middleware wiring
  - /services: Business logic (notes, tags, auth integration, summaries)
  - /db: Query layer (SQL or query builder), migrations/seeds
  - /middlewares: Auth guard, validation, error handler
- /infra: Deployment configs, CI, env samples
- /docs: Runbooks, API contracts

## 6. UI/UX PRINCIPLES
- Clean, minimal, Stripe/Notion/Linear-inspired; generous spacing, clear hierarchy.
- Minimize clicks; default sensible actions; inline validation.
- Fast load, responsive from mobile to desktop; dark-mode-friendly palette.
- Use consistent typography scale and color tokens; avoid visual noise.

## 7. BACKEND ARCHITECTURE
- API: RESTful routes under /api/v1.
- Flow: Request -> route -> auth middleware -> validation -> controller -> service -> db -> response.
- Controllers: Thin; translate HTTP to service calls and DTOs.
- Services: Contain business rules; orchestrate db + external APIs (LLM, auth).
- DB Layer: Parameterized queries; return typed objects.
- Errors: Standard error shape {message, code, details}; central error middleware maps to HTTP codes; log with context requestId/userId.

## 8. DATABASE DESIGN (Supabase/Postgres)
- tables:
  - users: id (pk, uuid), email (unique), name, created_at.
  - workspaces: id (pk, uuid), name, owner_id (fk users), created_at.
  - memberships: user_id (fk), workspace_id (fk), role (enum: owner, member), created_at, primary key (user_id, workspace_id), index on workspace_id.
  - notes: id (pk, uuid), workspace_id (fk), title, body, summary, is_public (bool), created_at, updated_at, deleted_at (nullable), index on (workspace_id, deleted_at).
  - tags: id (pk, uuid), workspace_id (fk), name, created_at; unique (workspace_id, lower(name)).
  - note_tags: note_id (fk), tag_id (fk), primary key (note_id, tag_id), index on tag_id.
  - activity: id (pk, uuid), note_id (fk), user_id (fk), action (enum), created_at, details (jsonb), index on note_id.

## 9. CODING RULES FOR AI
- Favor small, modular files; reusable components/hooks; no large god files.
- Keep naming consistent (camelCase for vars, PascalCase for components, kebab-case for files where appropriate).
- Add brief comments only for non-obvious logic.
- Avoid unnecessary deps; prefer stdlib + chosen stack.
- Keep functions pure where possible; isolate side effects.
- Validate inputs at boundaries (API, forms).

## 10. HACKATHON SPEED STRATEGY
- Build core flows first: auth -> create note -> view list/detail -> generate summary -> share link.
- Skip edge cases initially; add happy-path demo stability.
- Mock slow/complex services early; swap real integrations after UI is stable.
- Timebox features; keep scope small; keep demo script in mind.

## 11. ERROR HANDLING STRATEGY
- Frontend: Central fetch wrapper; show inline/toast errors; retry where safe; fallback UI for network errors.
- Backend: Central error middleware; return consistent JSON; sanitize messages; log stack traces server-side only.
- Distinguish user-facing messages from debug logs; never leak secrets.

## 12. PERFORMANCE RULES
- Backend: Use indexes above; avoid N+1 by joining/limiting fields; paginate lists.
- Frontend: Cache data (React Query/SWR); memoize expensive components; defer non-critical fetches.
- API: Keep payloads lean; use gzip/brotli by host; measure p95.

## 13. SECURITY BASELINES
- Validate all inputs (zod/valibot/yup); enforce auth on private routes.
- Rate limit sensitive endpoints (login, AI summarize).
- Use environment variables for secrets; never ship keys to client; lock CORS origins.
- Use HTTPS everywhere; set secure cookies if used.

## 14. AI CODING INSTRUCTIONS
- Think step-by-step; plan before writing.
- Follow the defined structure; do not refactor unrelated files.
- Keep diffs minimal and targeted; maintain compatibility with existing code and scripts.
- Prefer server-side calls for secrets; avoid client exposure.
- Write tests for core flows when time permits (Vitest/RTL on frontend, supertest on backend).

## 15. GIT WORKFLOW
- Small, frequent commits with clear messages.
- Keep main branch deployable; use feature branches if time allows; otherwise keep disciplined staging.
- Run lint/test before pushing when possible.

## 16. DEMO PREPARATION
- Seed data: create a few notes with tags and summaries; include one public note link.
- Onboarding: scripted path—sign in, create note, add tags, generate summary, share public link, show activity log.
- Prepare env samples (.env.example) and a short README snippet on setup/run.

## 17. FUTURE IMPROVEMENTS
- Real-time collaboration, comments, reminders, calendar integrations.
- Rich text/markdown editing, file uploads.
- Advanced search with embeddings; analytics dashboards.
- Role-based permissions per note/tag; workspace billing; audit logs.
- Mobile app or PWA offline mode.
