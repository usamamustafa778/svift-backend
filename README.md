# Svift Auth Backend

Simple Express + MongoDB email authentication API.

## Setup

1. Install dependencies:

```bash
cd backend
npm install
```

2. Create an `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

3. Update `MONGO_URI` and `JWT_SECRET` in `.env` as needed.

4. **Email (OTP):** Set `SMTP_USER` and `SMTP_PASS` in `.env` so OTP codes are sent by email. For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833). If not set, the code is only logged to the server console.

5. Start the server:

```bash
npm run dev
```

The API will run on `http://localhost:4000` by default.

## Endpoints

- `POST /auth/signup/start` – start signup with `{ email }`, creates a pending user and sends a 6‑digit OTP by email (or logs to console if SMTP is not configured).
- `POST /auth/verify-email` – verify signup OTP with `{ email, code }`, marks email as verified so password can be created.
- `POST /auth/signup/complete` – after OTP verification, set password with `{ email, password }`, returns a JWT.
- `POST /auth/login` – login with `{ email, password }`, may return `requiresVerification: true` if email not verified.
- `POST /auth/login/verify` – verify login with `{ email, code }`, returns a JWT.
- `POST /auth/otp/resend` – resend an OTP for an existing user with `{ email, context? }`.

