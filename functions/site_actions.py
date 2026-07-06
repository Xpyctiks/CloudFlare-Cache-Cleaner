from flask_login import current_user

def is_admin() -> bool:
  if not current_user.is_authenticated:
    return False
  rights = getattr(current_user, 'rights', '') or ''
  permissions = [item.strip().upper() for item in rights.split(',') if item.strip()]
  return 'ADMIN' in permissions or '255' in permissions
