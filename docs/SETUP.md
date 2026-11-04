# DevPulse Setup & Switch Console Connection Guide (Windows)

This document provides exact Windows (PowerShell) steps to configure, register, and run the `devpulse-gate` agent with your local Switch Console room.

---

## 1. Prerequisites

1. **Node.js**: v20 or later (v24 recommended). Verify in PowerShell:
   ```powershell
   node --version
   ```
2. **GitHub CLI (`gh`)**: Required for autonomous PR creation during verified approvals. Verify login:
   ```powershell
   gh auth status
   ```
3. **Switch Console**: Ensure your local Switch Console instance is running.

---

## 2. Configuration (`.env`)

Create your `.env` file in `C:\projects\DevPulse`:

```powershell
Copy-Item .env.example .env
```

Open `.env` and configure the following parameters:

```env
# Switch Server URL (probe GET /health to find your port)
SWITCH_CORE_URL=http://localhost:<PORT>

# Registration API Key obtained from Switch Gateway ("API Keys" page)
SWITCH_REGISTRATION_KEY=sw_reg_...

# Target Switch Room ID for devpulse-ops
SWITCH_ROOM_ID=room_...

# Maintainer Allowlist (Comma-separated Switch native user IDs allowed to approve)
MAINTAINER_ALLOWLIST=usr_...

# Internal cryptographic secret (min 32 characters)
DEVPULSE_APPROVAL_SECRET=your_secure_32_character_secret_key_here

# Local alert listener port
ALERT_PORT=3030
```

### Finding Your Switch Configuration Details

1. **Bridge Base URL (`SWITCH_CORE_URL`)**:
   - The bridge base URL exposes a `GET /health` endpoint.
   - Probe your running instance in PowerShell:
     ```powershell
     Invoke-RestMethod -Uri "http://localhost:<PORT>/health" -Method Get
     ```
   - A healthy status confirms the correct bridge URL. (If you get HTTP 401, the host is correct but the path differs; if ECONNREFUSED, verify the port).

2. **Registration Key (`SWITCH_REGISTRATION_KEY`)**:
   - In Switch Console, navigate to **Settings** / **Gateway** -> **API Keys**.
   - Create an API key with the **Registration** scope.
   - Paste into `.env` as `SWITCH_REGISTRATION_KEY` (never commit this key).

3. **Room ID (`SWITCH_ROOM_ID`)**:
   - In Switch Console, open the `devpulse-ops` room.
   - The room ID is displayed in the room settings or URL bar (e.g. `room_...`).

4. **Your Switch User ID (`MAINTAINER_ALLOWLIST`)**:
   - In Switch Console, click your user profile / avatar in the bottom-left corner or open the **Room Members** drawer.
   - Click on your name to inspect your native identifier (starts with `usr_...`).
   - Add this ID to `MAINTAINER_ALLOWLIST` in `.env`.

---

## 3. One-Time Agent Registration

Register the `devpulse-gate` agent with the Switch Gateway:

```powershell
npm run gate:register
```

**What this does:**
1. Validates `SWITCH_CORE_URL` and `SWITCH_REGISTRATION_KEY`.
2. Registers agent `devpulse-gate` via `POST /agents` with an `always_on` integration profile.
3. Configures addressing to `"anyone"` via `POST /agents/{id}/ops/update_agent_detail`.
4. Saves `SWITCH_AGENT_ID` and `SWITCH_AGENT_API_KEY` to `.env` without displaying secrets in output.

---

## 4. Running the DevPulse Gate

Start the gate agent:

```powershell
npm run gate
```

**Expected behavior:**
1. Connects to Switch Core WebSocket at `/agents/{agent_id}/connection/ws`.
2. Posts `"DevPulse Gate online"` into the `devpulse-ops` room.
3. Starts the local HTTP alert listener on `http://localhost:3030/alert`.

---

## 5. Local Verification

To test that the local HTTP alert listener is operational, run in another PowerShell window:

```powershell
Invoke-RestMethod -Uri "http://localhost:3030/health" -Method Get
```

Expected output:
```json
{ "status": "ok", "service": "devpulse-gate" }
```
