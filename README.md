# 🔐 Auth Boilerplate Fullstack (Nuxt 3 + NestJS + PostgreSQL + Docker)

Secure and scalable authentication boilerplate for modern fullstack apps. Features full token rotation, Docker setup, and Nuxt UI Pro integration.

---

## 🛠️ Tech Stack

- **Frontend**: Nuxt 3 + Nuxt UI Pro _(requires API key)_
- **Backend**: NestJS + TypeORM + PostgreSQL
- **Deployment**: Docker & Docker Compose (dev + production)

---

## ✨ Features

- ✅ Secure JWT authentication with rotating refresh tokens
- ✅ `HttpOnly` cookie storage for refresh tokens
- ✅ Access tokens stored in Pinia state (not `localStorage`)
- ✅ Automatic token refresh on `401 Unauthorized`
- ✅ Full logout (clears cookies and frontend state)
- ✅ Docker-ready setup for local development and production
- ✅ Structured to support social login / OAuth extensions

---

## 📦 Prerequisites

- [Node.js](https://nodejs.org/) v18+
- [Docker](https://www.docker.com/)
- Nuxt UI Pro license key _(free for development)_

---

## 🚀 Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/auth-boilerplate.git
cd auth-boilerplate
```
