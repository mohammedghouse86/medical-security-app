# MedSecure deployment

## Structure
- `frontend/`: React + Vite app for GitHub Pages
- `backend/`: Express API for Render
- `.github/workflows/deploy.yml`: GitHub Pages deployment

## GitHub Pages
The Vite base is currently `/medical-security-app/`. If your repository has another name, change `base` in `frontend/vite.config.mjs`.

Add a GitHub Actions repository variable:
- `VITE_API_URL` = your Render API URL, e.g. `https://medical-security-api.onrender.com`

## Render
Create a Web Service from this repository:
- Root Directory: `backend`
- Build Command: `npm install`
- Start Command: `npm start`
- Environment variable `FRONTEND_ORIGIN` = your GitHub Pages origin, e.g. `https://YOUR_USERNAME.github.io`

The API health check is `/api/health`.

## Local
Terminal 1:
```bash
cd backend
npm install
npm start
```

Terminal 2:
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173
