document.addEventListener("DOMContentLoaded", function () {
  const modalElement = document.getElementById("myModal");
  if (modalElement) {
    const modal = new bootstrap.Modal(modalElement);
    modal.show();
  }

  const form = document.querySelector("form");
  form.addEventListener("submit", (e) => {
    if (!form.checkValidity()) {
      return;
    }
    showLoading();
    form.querySelector("button[type=submit]").disabled = true;
  });

  form.addEventListener("invalid", () => {
    hideLoading();
  }, true);
});

function showLoading() {
  const spinner = document.getElementById("spinnerLoading");
  const spinner2 = document.getElementById("textLoading");
  if (spinner) {
    spinner.style.visibility = "visible";
  }
  if (spinner2) {
    spinner2.style.visibility = "visible";
  }
}

function hideLoading() {
  const spinner = document.getElementById("spinnerLoading");
  const spinner2 = document.getElementById("textLoading");
  if (spinner) {
    spinner.style.visibility = "hidden";
  } else {
    console.warn("Spinner element not found!");
  }
  if (spinner2) {
    spinner2.style.visibility = "hidden";
  } else {
    console.warn("Text element not found!");
  }
}

document.addEventListener("DOMContentLoaded", function () {
  hideLoading();
});

window.addEventListener("pageshow", function (event) {
  if (event.persisted) {
    hideLoading();
  }
});

var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
  return new bootstrap.Tooltip(tooltipTriggerEl)
})
