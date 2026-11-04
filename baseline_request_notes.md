# UMANG Chatbot — Baseline Request Notes

Captured manually from Chrome DevTools screenshots supplied for the assessment.

- Public UI: `https://web.umang.gov.in/ai_chatbot/`
- Request URL: `https://apigw.umangapp.in/agenticBotApi/api/agent/query`
- HTTP method: `POST`
- Observed baseline status: `200 OK`
- Request content type: JSON (the response content type shown was `application/json; charset=utf-8`)
- Observed request fields:
  - `question`: the latest user question
  - `previousChats`: an array with objects containing `role` and `content`; the screenshot showed a user entry
- Response keys observed: `success`, `answer`, `intents`, `schemes`, `language`, `isBrowse`, `authenticated`
- Example observed values: `success: true`, `intents: ["umang_service_info"]`, `language: "en"`, `isBrowse: false`, `authenticated: false`
- Authentication: response says `authenticated: false`; this does **not** prove whether the endpoint requires other request controls.
- Security caveat: screenshots do not establish written scope/authorization, rate limits, or whether this gateway is approved for direct automated testing. Confirm these with the guide/system owner first.
- No cookies, tokens, or secrets are stored in this project.
