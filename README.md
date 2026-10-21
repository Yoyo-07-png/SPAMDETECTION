# Gmail Email Analyzer

This Manifest V3 Chrome extension can search Gmail and download a selected message as `.eml`. It can also send the open message's EML to the local FastAPI scanner and display the report in the extension popup.

## Configure Google OAuth

1. Load this folder in Chrome at `chrome://extensions` using **Load unpacked**. Turn on **Developer mode** if needed.
2. Copy the extension ID shown on its card.
3. In Google Cloud Console, configure the Gmail API and OAuth consent screen. Add `https://www.googleapis.com/auth/gmail.readonly` as a scope and add your Google account as a test user if the consent screen is in testing.
4. Create an OAuth client ID of type **Chrome Extension**, using the extension ID from step 2.
5. Replace `YOUR_GOOGLE_OAUTH_CLIENT_ID.apps.googleusercontent.com` in `manifest.json` with that client ID, then reload the extension at `chrome://extensions`.

## Use

Open a Gmail conversation in a browser tab, open the extension, and click **Analyze open email**. The latest message in the conversation is fetched in raw EML form, sent to the API below, and its report is shown in the popup. Google will ask you to authorize read-only Gmail access the first time.

The search feature is also available: use Gmail search syntax (or leave the field empty to search the inbox), click **Find emails**, then choose **Download .eml** on a result.

## Start the local analysis API

From PowerShell:

```powershell
cd .\python
pip install -r requirements.txt
$env:CHROME_EXTENSION_ORIGINS = "chrome-extension://YOUR_EXTENSION_ID"
or
insert it 'in' the .env file. Make sure it exists 'in' the same directory as email_scam_thing_backend.py, and have the variable name be CHROME_EXTENSION_ORIGINS as above.
uvicorn email_scam_thing_backend:app --host 127.0.0.1 --port 8000
```

Get `YOUR_EXTENSION_ID` from `chrome://extensions`. Keep the API bound to `127.0.0.1`; the extension posts the EML file to `http://127.0.0.1:8000/analyze`. The API accepts EML uploads up to 10 MiB and permits browser requests only from the configured extension origin. Restart the API if you change the environment variable.

After updating the extension, reload it at `chrome://extensions` to apply its local API host permission and any other manifest changes.

The email is sent to the configured local API for analysis; it is not sent to a separate hosted service by this extension.
