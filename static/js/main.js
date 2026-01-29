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
  if (spinner) {
    spinner.style.visibility = "hidden";
  } else {
    console.warn("Spinner element not found!");
  }
}

document.addEventListener("DOMContentLoaded", function () {
  loadDomains();
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

const btn = document.getElementById("scrollTopBtn");
window.addEventListener("scroll", () => {
  if (window.scrollY > 300) {
    btn.style.display = "block";
  } else {
    btn.style.display = "none";
  }
});

btn.addEventListener("click", () => {
  window.scrollTo({
    top: 0,
    behavior: "smooth"
  });
});

function applyFilters() {
  const owner = document.getElementById("accountFilter").value;
  const text  = document.getElementById("domainFilter")?.value || "";

  document.querySelectorAll("tbody tr").forEach(row => {
    const rowOwner = row.dataset.owner || "";
    const rowText  = row.innerText.toLowerCase();
    const matchOwner = !owner || rowOwner === owner;
    const matchText  = !text || rowText.includes(text);
    row.style.display = (matchOwner && matchText) ? "" : "none";
  });
}

document.getElementById("accountFilter").addEventListener("change", applyFilters);
document.getElementById("domainFilter").addEventListener("input", applyFilters);

function clearFilters() {
  const siteFilter  = document.getElementById("domainFilter");
  if (siteFilter) siteFilter.value = "";
  applyFilters();
}

document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") {
    clearFilters();
  }
});

async function loadDomains() {
  const overlayLoader = document.getElementById("overlayLoader");
  const tbody = document.getElementById("domainsTableBody");
  const menu = document.getElementById("accountFilter");

  function extract(html, start, end) {
    const s = html.indexOf(start);
    const e = html.indexOf(end);
    if (s === -1 || e === -1 || e <= s) {
      console.warn(`Fragment not found: ${start}`);
      return "";
    }
    return html.slice(s + start.length, e).trim();
  }

  overlayLoader.classList.remove("d-none");
  try {
    const response = await fetch("/data");
    const html = await response.text();
    tbody.innerHTML = extract(html, "<!-- TABLE_START -->", "<!-- TABLE_END -->");
    menu.innerHTML  = extract(html, "<!-- MENU_START -->", "<!-- MENU_END -->");
  } catch (err) {
    console.error(err);
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="text-danger text-center">
          Помилка завантаження
        </td>
      </tr>
    `;
  } finally {
    overlayLoader.classList.add("d-none");
  }
}
