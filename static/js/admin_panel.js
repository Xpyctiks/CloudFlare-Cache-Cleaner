document.addEventListener('DOMContentLoaded', function () {
  var modalEl = document.getElementById('flashModal');
  if (modalEl) {
    var modal = new bootstrap.Modal(modalEl);
    modal.show();
  }
});

document.querySelectorAll('.account-name-edit').forEach(function (el) {
  el.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      el.blur();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      el.textContent = el.dataset.originalName;
      el.blur();
    }
  });

  el.addEventListener('blur', function () {
    var newName = el.textContent.trim();
    var originalName = el.dataset.originalName;
    if (!newName) {
      el.textContent = originalName;
      return;
    }
    if (newName === originalName) {
      el.textContent = newName;
      return;
    }
    fetch('/admin_panel/accounts/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: el.dataset.accountId, name: newName })
    })
    .then(function (response) { return response.json().then(function (data) { return { ok: response.ok, data: data }; }); })
    .then(function (result) {
      if (result.ok && result.data.success) {
        el.dataset.originalName = result.data.name;
        el.textContent = result.data.name;
      } else {
        el.textContent = originalName;
        alert(result.data.message || 'Не вдалося зберегти назву.');
      }
    })
    .catch(function () {
      el.textContent = originalName;
      alert('Не вдалося зберегти назву.');
    });
  });
});
