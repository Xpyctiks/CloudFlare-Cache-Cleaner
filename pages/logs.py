from flask import Blueprint, render_template, current_app
from flask_login import login_required
import logging
from pathlib import Path
from collections import deque
from functions.site_actions import is_admin

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/logs/", methods=['GET'])
@login_required
def show_logs():
  try:
    log_path = current_app.config.get('LOG_FILE', '')
    log_text = ''
    error_message = ''
    if not log_path:
      error_message = 'Шлях до лог-файлу не визначено.'
    else:
      path = Path(log_path)
      if not path.exists():
          error_message = f'Файл логів не знайдено: {log_path}'
      else:
          with path.open('r', encoding='utf-8', errors='replace') as f:
              lines = deque(f, maxlen=300)
          log_text = ''.join(lines)
    return render_template('template-logs.html', log_lines=log_text, log_path=log_path, error_message=error_message, is_admin=is_admin())
  except Exception as err:
    logging.error(f'show_logs(): global error {err}')
    error_message = 'Не вдалося завантажити логи.'
    return render_template('template-logs.html', log_lines='', log_path='', error_message=error_message, is_admin=is_admin())
