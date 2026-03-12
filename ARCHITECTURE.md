# ARCHITECTURE

## System Architecture Overview
This document defines the architectural structure of the project. All AI coding assistants must strictly follow this architecture to maintain consistency, speed, and reliability during development. The system uses a modern full-stack design optimized for rapid hackathon delivery while keeping production-quality standards.

## High Level Architecture
Frontend (UI Layer)
↓
API Layer
↓
Business Logic Layer
↓
Database Layer

Communication Flow: User → Frontend → API Routes → Services → Database → Response → Frontend

## Technology Stack
Frontend
- Next.js (React framework)
- TailwindCSS for styling
- React hooks for state management

Backend
- Node.js
- Express.js OR FastAPI (depending on project setup)

Database
- PostgreSQL OR Supabase

Authentication
- Supabase Auth / Firebase Auth / Clerk

Deployment
- Vercel (Frontend)
- Render / Railway (Backend)

AI Integration (if needed)
- OpenAI API
- HuggingFace models
- Custom inference APIs

## Project Folder Structure
/frontend
- components/ — Reusable UI components
- pages/ or app/ — Application routes and pages
- hooks/ — Custom React hooks
- services/ — API request functions
- styles/ — Global styling
- utils/ — Helper functions

/backend
- controllers/ — Handles API request logic
- routes/ — Defines API endpoints
- services/ — Business logic
- middlewares/ — Authentication / validation
- config/ — Environment configs

/database
- schema/ — Database schemas
- migrations/ — Database migration files
- seed/ — Demo data for hackathon presentation

## Frontend Architecture
Component-driven architecture.
Principles:
- Components must be reusable.
- UI must be clean and minimal.
- State handled via hooks.
- API communication goes through the services layer.
- Avoid complex state libraries unless necessary.

Example: Dashboard Page → Dashboard Layout → Feature Components → API Services.

## Backend Architecture
Layered architecture.
- Routes Layer: Defines endpoints.
- Controllers Layer: Handles request validation and response.
- Services Layer: Core business logic.
- Database Layer: Queries and persistence.

Example flow: POST /api/task → Route → Controller → Service → Database → Response.

## API Design Principles
- RESTful endpoints (e.g., GET /api/users, POST /api/tasks, PUT /api/tasks/:id, DELETE /api/tasks/:id).
- Success response: { success: true, data: {}, message: "" }.
- Error response: { success: false, error: "error message" }.

## Database Design
Keep schema simple.
Core tables: Users; Tasks or other core entities; Logs (optional).
Rules: use UUIDs; include created_at and updated_at; add indexes on frequently queried fields.

## Error Handling
Backend: try/catch with centralized error middleware. Frontend: user-friendly messages and fallback UI components.

## Security Baselines
- Validate all user inputs.
- Use environment variables for secrets.
- Never expose API keys.
- Enable basic rate limiting.
- Sanitize database inputs.

## Performance Considerations
- Avoid unnecessary API calls.
- Use caching where possible.
- Lazy load heavy UI components.
- Optimize database queries.

## AI Assistant Coding Rules
1. Do not modify unrelated files.
2. Follow the existing folder structure.
3. Prefer reusable components.
4. Write clear function names.
5. Keep files under 300 lines when possible.
6. Add comments for complex logic.
7. Avoid unnecessary libraries.

## Hackathon Development Strategy
Goal: build a working MVP first.
Priority order: Core functionality → Basic UI → Database integration → Error handling → UI polish → Optional advanced features. Ignore edge cases until the MVP works.

## Demo Preparation
For presentation: include seeded demo data; ensure onboarding works instantly; avoid login friction if possible; prepare a smooth demo flow.
