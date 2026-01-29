import logging,httpx
from flask import current_app

async def send_to_telegram(message: str, subject: str = f"Cloud-cache-cleaner", ) -> None:
  """Sends messages via Telegram if TELEGRAM_CHATID and TELEGRAM_TOKEN are both set. Requires "message" parameters and can accept "subject" """
  TELEGRAM_CHATID: str = current_app.config["TELEGRAM_CHATID"]
  TELEGRAM_TOKEN: str = current_app.config["TELEGRAM_TOKEN"]
  if TELEGRAM_CHATID and TELEGRAM_TOKEN:
    headers = {
      'Content-Type': 'application/json',
    }
    data = {
      "chat_id": f"{TELEGRAM_CHATID}",
      "text": f"{subject}\n{message}",
    }
    try:
      async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
          f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
          headers=headers,
          json=data
        )
      print(response.status_code)
      if response.status_code != 200:
        logging.error(f"Telegram bot error! Status: {response.status_code} Body: {response.text}")
    except Exception as err:
      logging.error(f"Error while sending message to Telegram: {err}")
