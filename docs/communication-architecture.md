# WARVEX Communication System

Status: UI scaffold added to the shared app at `app/index.html`. External integrations are not connected yet.

## Target architecture

### 1. WhatsApp Business messaging
- Use the official WhatsApp Business Platform Cloud API only.
- Meta sends incoming business-number messages to a verified HTTPS webhook.
- A Cloudflare Worker validates the webhook and signature, normalizes the event, and passes only the required message content to the WARVEX AI service.
- WARVEX creates a reply draft. Sending should require explicit approval at first; automatic replies can be enabled later only for a clearly defined business workflow.
- Keep Meta access tokens, app secrets, verify tokens, and phone-number IDs in Cloudflare Worker secrets, never in browser JavaScript or GitHub.
- This does not read a personal WhatsApp inbox or old private chat history.

### 2. WARVEX LIVE rooms
- Use a separate WebRTC room service (planned: LiveKit) for multi-person audio/video.
- A secure backend issues short-lived room tokens after the host creates a room and invites participants.
- A WARVEX voice/vision agent joins as a clearly labeled participant.
- The agent receives only media that participants explicitly publish. Camera and microphone controls remain visible; participants can mute, stop video, or remove the agent.
- The AI may sample frames for visual understanding; it must not silently record calls. Tell every participant when the AI is present and processing audio/video.
- This is a WARVEX-hosted room, not an AI bot silently joining a normal WhatsApp group video call.

## Required setup before production
1. An adult account owner/guardian must manage Meta Business and developer registration and approve the business number and permissions.
2. Create a Meta app and WhatsApp Business Platform test setup. Configure a public HTTPS webhook and verify token.
3. Configure Worker secrets: `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_VERIFY_TOKEN`, and `META_APP_SECRET`.
4. Add secure webhook event storage/queue and connect it to the WARVEX AI endpoint.
5. Create a LiveKit project and configure server-side API key/secret. Never place these in the PWA.
6. Deploy a WARVEX LiveKit agent with an audio/video-capable model and connect it to the existing WARVEX assistant logic.
7. Test with consenting participants and a test number before enabling any real messaging.

## Current implementation
- The shared app now has a **KOMMUNIKATION** section.
- Voice command: “Hey WARVEX, öffne Kommunikation”.
- The page explains the setup requirements and links to official technical documentation.
- Status labels deliberately say “not connected”. No real WhatsApp message is read or sent and no live room is created yet.

## Official technical references
- WhatsApp Business Platform: https://developers.facebook.com/docs/whatsapp/cloud-api/
- WhatsApp Business Developer Hub: https://whatsappbusiness.com/developers/developer-hub/
- LiveKit Agents: https://docs.livekit.io/agents/
- LiveKit video input: https://docs.livekit.io/agents/multimodality/vision/video/
