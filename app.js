const API_URL = "http://localhost:8000";
let token = "";
let transacciones = [];

// --- Elementos del DOM ---
const modal = document.getElementById("loginModal");
const abrirLogin = document.getElementById("abrirLogin");
const cerrarModal = document.getElementById("cerrarModal");
const btnLogin = document.getElementById("btnLogin");
const cerrarSesionBtn = document.getElementById("cerrarSesion");
const loginMsg = document.getElementById("loginMsg");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");

const transactionForm = document.getElementById("transaction-form");
const transactionTable = document.querySelector("#transaction-table tbody");
const filtroNombre = document.getElementById("filtroNombre");
const filtroTipo = document.getElementById("filtroTipo");
const filtroFecha = document.getElementById("date");
const pieChartCanvas = document.getElementById("pieChart");
const barChartCanvas = document.getElementById("barChart");
const diferenciaDiv = document.getElementById("diferencia");
const campoFecha = document.getElementById("transactionDate");

// Modal de edición
const editModal = document.getElementById("editModal");
const editDescripcion = document.getElementById("editDescripcion");
const editMonto = document.getElementById("editMonto");
const editTipo = document.getElementById("editTipo");
const editFecha = document.getElementById("editFecha");
const guardarEdicion = document.getElementById("guardarEdicion");
const cancelarEdicion = document.getElementById("cancelarEdicion");
let transaccionEditando = null;

let pieChart, barChart;
let rolUsuario = ""; // para saber si es admin o usuario

// --- Manejo de modales ---
abrirLogin.onclick = () => (modal.style.display = "flex");
cerrarModal.onclick = () => (modal.style.display = "none");
cancelarEdicion.onclick = () => {
  editModal.style.display = "none";
  transaccionEditando = null;
};

// --- Login ---
btnLogin.onclick = async () => {
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();

  if (!username || !password) {
    loginMsg.textContent = "Completa ambos campos.";
    return;
  }

  try {
    const res = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (data.token) {
      token = data.token;
      localStorage.setItem("token", token);
      modal.style.display = "none";
      mostrarDashboard();
      await cargarTransacciones();
    } else {
      loginMsg.textContent = data.message || "Credenciales inválidas.";
    }
  } catch (err) {
    loginMsg.textContent = "Error de conexión con el servidor.";
  }
};

// --- Cerrar sesión ---
cerrarSesionBtn.onclick = () => {
  localStorage.removeItem("token");
  token = "";
  location.reload();
};

// --- Mostrar Dashboard ---
function mostrarDashboard() {
  document.getElementById("transaction-form").style.display = "flex";
  document.querySelector(".filtros").style.display = "block";
  document.querySelector(".graficoSelect").style.display = "block";
  cerrarSesionBtn.style.display = "inline-block";
  abrirLogin.style.display = "none";
}

// --- Cargar Transacciones ---
async function cargarTransacciones() {
  try {
    const res = await fetch(`${API_URL}/transacciones`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`Error ${res.status}`);
    transacciones = await res.json();
    transacciones = transacciones.map((t) => ({
      ...t,
      Monto: Number(t.Monto) || 0,
    }));
    // Detectar rol del usuario actual (admin o usuario)
    const payload = JSON.parse(atob(token.split(".")[1]));
    rolUsuario = payload.rol;

    renderTabla();
    actualizarGraficos();
  } catch (err) {
    console.error("Error al cargar transacciones:", err);
    if (err.message.includes("401") || err.message.includes("403")) {
      alert("Sesión expirada. Vuelve a iniciar sesión.");
      localStorage.removeItem("token");
      token = "";
      location.reload();
    }
  }
}

// --- Agregar Transacción ---
transactionForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const fechaSeleccionada =
    campoFecha.value || new Date().toISOString().split("T")[0];

  const nueva = {
    tipo: document.getElementById("type").value,
    monto: parseFloat(document.getElementById("amount").value),
    descripcion: document.getElementById("description").value,
    fecha: fechaSeleccionada,
  };

  try {
    const res = await fetch(`${API_URL}/transacciones`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(nueva),
    });
    if (!res.ok) throw new Error(`Error ${res.status}`);
    await cargarTransacciones();
    transactionForm.reset();
  } catch (err) {
    console.error("Error al agregar transacción:", err);
    alert("No se pudo agregar. Verifica tu sesión.");
  }
});

// --- Renderizar Tabla ---
function renderTabla() {
  transactionTable.innerHTML = "";
  const nombreFiltro = filtroNombre.value;
  const tipoFiltro = filtroTipo.value;
  const fechaFiltro = filtroFecha.value;

  const filtradas = transacciones.filter((t) => {
    return (
      (nombreFiltro === "todos" || t.username === nombreFiltro) &&
      (tipoFiltro === "todos" || t.Tipo === tipoFiltro) &&
      (!fechaFiltro || t.Fecha === fechaFiltro)
    );
  });

  filtradas.forEach((t) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${t.username || "Usuario"}</td>
      <td>${t.Tipo}</td>
      <td>S/ ${t.Monto.toFixed(2)}</td>
      <td>${t.Descripción}</td>
      <td>${t.Fecha}</td>
      <td>
        ${
          rolUsuario === "admin"
            ? ""
            : `<button class="editar" data-id="${t.Id}">✏️</button>
               <button class="eliminar" data-id="${t.Id}">🗑️</button>`
        }
      </td>
    `;
    transactionTable.appendChild(row);
  });

  if (rolUsuario !== "admin") {
    document.querySelectorAll(".eliminar").forEach((btn) => {
      btn.addEventListener("click", () => eliminarTransaccion(btn.dataset.id));
    });

    document.querySelectorAll(".editar").forEach((btn) => {
      btn.addEventListener("click", () => abrirEdicion(btn.dataset.id));
    });
  }
}

// --- Eliminar Transacción ---
async function eliminarTransaccion(id) {
  try {
    const res = await fetch(`${API_URL}/transacciones/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`Error ${res.status}`);
    await cargarTransacciones();
  } catch (err) {
    console.error("Error al eliminar:", err);
    alert("No se pudo eliminar la transacción.");
  }
}

// --- Editar Transacción ---
function abrirEdicion(id) {
  const transaccion = transacciones.find((t) => t.Id == id);
  if (!transaccion) return;

  transaccionEditando = id;
  editDescripcion.value = transaccion.Descripción;
  editMonto.value = transaccion.Monto;
  editTipo.value = transaccion.Tipo;
  editFecha.value = transaccion.Fecha;

  editModal.style.display = "flex";
}

guardarEdicion.onclick = async () => {
  if (!transaccionEditando) return;

  const cambios = {
    descripcion: editDescripcion.value,
    monto: parseFloat(editMonto.value),
    tipo: editTipo.value,
    fecha: editFecha.value || new Date().toISOString().split("T")[0],
  };

  try {
    const res = await fetch(`${API_URL}/transacciones/${transaccionEditando}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(cambios),
    });
    if (!res.ok) throw new Error(`Error ${res.status}`);

    editModal.style.display = "none";
    transaccionEditando = null;
    await cargarTransacciones();
  } catch (err) {
    console.error("Error al editar:", err);
    alert("No se pudo editar la transacción.");
  }
};

// --- Graficar Datos ---
function actualizarGraficos() {
  const ingresos = transacciones
    .filter((t) => t.Tipo === "ingreso")
    .reduce((sum, t) => sum + t.Monto, 0);
  const gastos = transacciones
    .filter((t) => t.Tipo === "gasto")
    .reduce((sum, t) => sum + t.Monto, 0);

  const diferencia = ingresos - gastos;
  diferenciaDiv.textContent = `Diferencia: $${diferencia.toFixed(2)}`;

  if (pieChart) pieChart.destroy();
  pieChart = new Chart(pieChartCanvas, {
    type: "pie",
    data: {
      labels: ["Ingresos", "Gastos"],
      datasets: [
        { data: [ingresos, gastos], backgroundColor: ["#4caf50", "#f44336"] },
      ],
    },
  });

  if (barChart) barChart.destroy();
  const resumenMensual = agruparPorMes(transacciones);
  barChart = new Chart(barChartCanvas, {
    type: "bar",
    data: {
      labels: Object.keys(resumenMensual),
      datasets: [
        {
          label: "Ingresos",
          data: Object.values(resumenMensual).map((v) => v.ingresos),
          backgroundColor: "#4caf50",
        },
        {
          label: "Gastos",
          data: Object.values(resumenMensual).map((v) => v.gastos),
          backgroundColor: "#f44336",
        },
      ],
    },
  });
}

// --- Agrupar por Mes ---
function agruparPorMes(transacciones) {
  const resumen = {};
  transacciones.forEach((t) => {
    const mes = t.Fecha.slice(0, 7);
    if (!resumen[mes]) resumen[mes] = { ingresos: 0, gastos: 0 };
    resumen[mes][t.Tipo === "ingreso" ? "ingresos" : "gastos"] += t.Monto;
  });
  return resumen;
}

// --- Filtros ---
[filtroNombre, filtroTipo, filtroFecha].forEach((f) =>
  f.addEventListener("change", () => {
    renderTabla();
    actualizarGraficos();
  })
);

// --- Mantener sesión ---
if (localStorage.getItem("token")) {
  token = localStorage.getItem("token");
  mostrarDashboard();
  cargarTransacciones();
}
// --- Cerrar sesión manual ---
cerrarSesionBtn.onclick = () => {
  sessionStorage.setItem("cerradoManual", "true"); // Marcamos que cerró manualmente
  localStorage.removeItem("token");
  token = "";
  location.reload();
};

// --- Siempre cerrar sesión al abrir o recargar ---
if (
  !sessionStorage.getItem("redirected") &&
  !sessionStorage.getItem("cerradoManual")
) {
  alert("Tu sesión ha caducado. Ingresa nuevamente.");
  localStorage.removeItem("token");
  token = "";

  sessionStorage.setItem("redirected", "true");
  window.location.href = "/";
} else {
  sessionStorage.removeItem("redirected");
  sessionStorage.removeItem("cerradoManual"); // Resetea para próximas veces
}
