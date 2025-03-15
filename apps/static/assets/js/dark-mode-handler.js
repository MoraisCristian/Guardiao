const themeSwitch = document.getElementById("theme-switch");
const themeIndicator = document.getElementById("theme-indicator");
const page = document.body;

const themeStates = ["light", "dark"];
const indicators = ["fa-sun", "fa-moon"];
const pageClass = ["bg-gray-100", "dark-page"];

let currentTheme = localStorage.getItem("theme");

function setTheme(theme) {
  localStorage.setItem("theme", themeStates[theme]);
}

function setIndicator(theme) {
  themeIndicator.classList.remove(indicators[0]);
  themeIndicator.classList.remove(indicators[1]);
  themeIndicator.classList.add(indicators[theme]);
}

function setPage(theme) {
  page.classList.remove(pageClass[0]);
  page.classList.remove(pageClass[1]);
  page.classList.add(pageClass[theme]);
}

// Inicialização do tema
document.addEventListener("DOMContentLoaded", function() {
  // Verificar se os elementos existem
  if (!themeSwitch || !themeIndicator) {
    console.error("Elementos de tema não encontrados.");
    return;
  }
  
  // Inicializar tema - Invertendo a lógica para que checked = dark mode
  if (currentTheme === null) {
    localStorage.setItem("theme", themeStates[0]);
    setIndicator(0);
    setPage(0);
    themeSwitch.checked = false;
  } else if (currentTheme === themeStates[0]) {
    setIndicator(0);
    setPage(0);
    themeSwitch.checked = false;
  } else if (currentTheme === themeStates[1]) {
    setIndicator(1);
    setPage(1);
    themeSwitch.checked = true;
  }
  
  // Adicionar listener ao switch - Invertendo a lógica
  themeSwitch.addEventListener("change", function () {
    if (this.checked) {
      setTheme(1); // Dark
      setIndicator(1);
      setPage(1);
    } else {
      setTheme(0); // Light
      setIndicator(0);
      setPage(0);
    }
  });
});

// Inicializar os botões de configuração
document.addEventListener("DOMContentLoaded", function() {
  // Botão para abrir o painel de configurações
  const fixedPlugin = document.querySelector('.fixed-plugin');
  const fixedPluginButton = document.querySelector('.fixed-plugin-button');
  const fixedPluginCloseButton = document.querySelector('.fixed-plugin-close-button');
  
  if (fixedPluginButton && fixedPlugin) {
    fixedPluginButton.addEventListener('click', function() {
      fixedPlugin.classList.toggle('show');
    });
  }
  
  if (fixedPluginCloseButton && fixedPlugin) {
    fixedPluginCloseButton.addEventListener('click', function() {
      fixedPlugin.classList.remove('show');
    });
  }
});

// Função para adicionar o toggle ao DOM se não existir
function addThemeToggleToDOM() {
  const navbar = document.querySelector('.navbar-nav') || document.querySelector('nav') || document.body;
  
  if (navbar) {
    const toggleContainer = document.createElement('li');
    toggleContainer.className = 'nav-item d-flex align-items-center';
    
    toggleContainer.innerHTML = `
      <div class="form-check form-switch ps-2 ms-auto my-auto">
        <input class="form-check-input mt-1 ms-auto" type="checkbox" id="theme-switch" checked>
        <i class="fa fa-moon ms-2" id="theme-indicator"></i>
      </div>
    `;
    
    navbar.appendChild(toggleContainer);
    
    // Atualizar referências aos elementos
    themeSwitch = document.getElementById("theme-switch");
    themeIndicator = document.getElementById("theme-indicator");
  }
}

// Código para status badges
document.addEventListener("DOMContentLoaded", function () {
  const statusBadgeList = document.querySelectorAll("#statusBadge");

  statusBadgeList.forEach(function (statusBadge) {
    const textContent = statusBadge.textContent.trim();

    switch (textContent) {
      case "Inativo":
        statusBadge.classList.remove("bg-gradient-success");
        statusBadge.classList.add("bg-gradient-secondary");
        break;
      case "HIGH":
        statusBadge.classList.remove("bg-gradient-success");
        statusBadge.classList.add("bg-gradient-warning");
        break;
      case "CRITICAL":
        statusBadge.classList.remove("bg-gradient-success");
        statusBadge.classList.add("bg-gradient-danger");
        break;
      case "MEDIUM":
        statusBadge.classList.remove("bg-gradient-success");
        statusBadge.classList.add("bg-gradient-info");
        break;
      default:
        // Handle any other cases here
        break;
    }
  });
});
