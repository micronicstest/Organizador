const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 8000;

// --- Configuración de MariaDB ---
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "Root",
  database: "control_gastos",
};

let db;
(async () => {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log("Conectado a MariaDB");
  } catch (err) {
    console.error("Error conectando a MariaDB:", err);
  }
})();

const JWT_SECRET = "clave_super_segura";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Middleware para verificar token ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Falta token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
}

// --- Login ---
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await db.execute(
      "SELECT * FROM usuarios WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Usuario no encontrado" });
    }

    const user = rows[0];
    if (password !== user.password) {
      return res.status(401).json({ message: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, rol: user.rol },
      JWT_SECRET
    );

    res.json({ message: "Login exitoso", token });
  } catch (error) {
    console.error("Error en /login:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// --- Obtener transacciones ---
app.get("/transacciones", authenticateToken, async (req, res) => {
  try {
    console.log("Usuario autenticado:", req.user);

    let query = `
      SELECT t.Id, t.Tipo, t.Monto, t.Descripción, t.Fecha, u.username 
      FROM transacciones t
      JOIN usuarios u ON t.usuario_id = u.id
    `;
    const params = [];

    if (req.user.rol !== "admin") {
      query += " WHERE t.usuario_id = ?";
      params.push(req.user.id);
    }

    console.log("Ejecutando SQL:", query, params);

    const [rows] = await db.execute(query, params);
    res.json(rows || []); // Devuelve [] si no hay transacciones
  } catch (error) {
    console.error("Error en /transacciones:", error);
    res.status(500).json({ message: "Error al obtener transacciones" });
  }
});

// --- Crear transacción ---
app.post("/transacciones", authenticateToken, async (req, res) => {
  try {
    const { tipo, monto, descripcion, fecha } = req.body;

    const [result] = await db.execute(
      "INSERT INTO transacciones (usuario_id, Tipo, Monto, Descripción, Fecha) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, tipo, monto, descripcion, fecha]
    );

    res.status(201).json({
      Id: result.insertId,
      Tipo: tipo,
      Monto: monto,
      Descripción: descripcion,
      Fecha: fecha,
      usuario_id: req.user.id,
    });
  } catch (error) {
    console.error("Error en POST /transacciones:", error);
    res.status(500).json({ message: "Error al crear transacción" });
  }
});

// --- Editar transacción ---
app.put("/transacciones/:id", authenticateToken, async (req, res) => {
  if (req.user.rol === "admin") {
    return res
      .status(403)
      .json({ message: "El administrador no puede editar transacciones" });
  }

  try {
    const { id } = req.params;
    const { tipo, monto, descripcion, fecha } = req.body;

    const [result] = await db.execute(
      "UPDATE transacciones SET Tipo = ?, Monto = ?, Descripción = ?, Fecha = ? WHERE Id = ? AND usuario_id = ?",
      [tipo, monto, descripcion, fecha, id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "No se encontró la transacción o no tienes permiso" });
    }

    res.json({ message: "Transacción actualizada" });
  } catch (error) {
    console.error("Error en PUT /transacciones:", error);
    res.status(500).json({ message: "Error al actualizar transacción" });
  }
});

// --- Eliminar transacción ---
app.delete("/transacciones/:id", authenticateToken, async (req, res) => {
  if (req.user.rol === "admin") {
    return res
      .status(403)
      .json({ message: "El administrador no puede eliminar transacciones" });
  }

  try {
    const { id } = req.params;

    const [result] = await db.execute(
      "DELETE FROM transacciones WHERE Id = ? AND usuario_id = ?",
      [id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "No se encontró la transacción o no tienes permiso" });
    }

    res.json({ message: "Transacción eliminada" });
  } catch (error) {
    console.error("Error en DELETE /transacciones:", error);
    res.status(500).json({ message: "Error al eliminar transacción" });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
