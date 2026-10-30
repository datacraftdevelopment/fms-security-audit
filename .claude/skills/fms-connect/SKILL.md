---
name: fms-connect
description: Help the consultant store FileMaker Server and OttoFMS credentials safely and test the connection. Use before any server collection step.
---

# Connect to the server

1. Tell the consultant to open a **separate terminal window** (not this chat) and run:
   `python -m audit login <host>`
   It prompts for the Admin Console username and password, without echoing them. Add `--otto` only if OttoFMS uses different credentials, and stores them in the OS keychain.
2. Never ask them to type or paste a password here. If one appears in the chat, tell them to have it changed.
3. Run `python -m audit check-connection <host>` to confirm the Admin API login works. It prints only success or the error.
4. If it fails:
   - Can they open `https://<host>/admin-console` in a browser from this computer? If not, it's network or VPN.
   - A certificate warning is itself a finding (SRV-02). Continue only if the consultant confirms with the client.
   - Wrong password: run `audit login` again.
