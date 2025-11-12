# node-ts-project-modular

Structure:
- server.js (only JS)
- src/ (TypeScript)
  - app.ts
  - config/db.ts
  - middlewares/{auth,role,logger}.ts
  - modules/
    - auth/ (register, login, role)
    - lead/ (lead CRUD, sanitize, routes, model)
  - utils/validation.ts

Run locally:
1. cp .env.example .env and fill values
2. npm install
3. npm run dev

Notes:
- server.js uses ts-node/register so TypeScript files run directly.
- Leads include createdBy (user id) and sNo auto-increment using a counters collection.
