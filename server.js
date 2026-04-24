require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= UPLOAD FOLDERS =================
const uploadDirs = {
  profile: path.join(__dirname, 'uploads/profile'),
  transcript: path.join(__dirname, 'uploads/transcript'),
  certificate: path.join(__dirname, 'uploads/certificate'),
  eventphoto: path.join(__dirname, 'uploads/eventphoto')
};

// ================= MULTER STORAGE CONFIG =================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, WebP allowed'));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 20 * 1024 * 1024 }
});

// ================= STATIC FILES =================
app.use('/uploads', express.static(path.join(__dirname, 'public_html/uploads')));

const SALT_ROUNDS = 10;
const ALLOWED_TYPES = ["UNIVERSITY", "ORGANIZER"];

// ========== DATABASE CONNECTION ==========
const db = mysql.createPool({
  host: "localhost",
  user: "zemrmpsz",
  password: "Etdit11@pim",
  database: "zemrmpsz_dailylifes",
  port: 3306,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ✅ SET NAMES ทุก connection ใหม่ใน pool
db.on('connection', (connection) => {
  connection.query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
});

// Health-check
db.getConnection((err, connection) => {
  if (err) {
    console.log("❌ Database Error:", err);
  } else {
    connection.query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci", (err) => {
      if (err) console.log("❌ SET NAMES Error:", err);
      else console.log("✅ MySQL Pool Connected + UTF8MB4 Set!");
      connection.release();
    });
  }
});

// ========== FILE UPLOAD HELPER (Local Storage) ==========
const uploadFileLocal = (file, folder) => {
  if (!file) return null;

  const allowed = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowed.includes(file.mimetype)) {
    throw new Error('Invalid file type');
  }

  const relativePath = `/uploads/${folder}/${file.filename}`;
  return relativePath;
};

// ========== JWT MIDDLEWARE ==========
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'] || req.headers['Authorization'];
  console.log('Authorization header:', auth);

  if (!auth) {
    return res.status(401).json({ message: 'Invalid token - no Authorization header' });
  }

  const parts = auth.trim().split(/\s+/);
  console.log('Authorization parts:', parts);

  if (parts.length !== 2 || !/^Bearer$/i.test(parts[0])) {
    return res.status(401).json({ message: 'Invalid token - bad format' });
  }

  const token = parts[1];

  console.log('JWT secret present:', !!process.env.JWT_SECRET, 'len=', process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0);
  console.log('JWT public key present:', !!process.env.JWT_PUBLIC_KEY);

  let header = null;
  try {
    const headerB64 = token.split('.')[0];
    header = JSON.parse(Buffer.from(headerB64, 'base64').toString('utf8'));
    console.log('Token header:', header);
  } catch (e) {
    console.warn('Could not decode token header:', e && e.message);
  }

  const alg = header && header.alg ? header.alg : null;

  if (alg === 'RS256') {
    const pubKey = process.env.JWT_PUBLIC_KEY;
    if (!pubKey) {
      console.error('RS256 token but JWT_PUBLIC_KEY not set');
      return res.status(401).json({ message: 'Invalid token - missing public key for RS256' });
    }
    jwt.verify(token, pubKey, { algorithms: ['RS256'] }, (err, decoded) => {
      if (err) {
        console.error('JWT verify error (RS256):', err && err.message);
        return res.status(401).json({ message: 'Invalid token - verify failed', error: err && err.message });
      }
      console.log('JWT decoded (RS256):', decoded);
      req.user = decoded;
      next();
    });
    return;
  }

  const secret = process.env.JWT_SECRET || "change_this_secret";
  jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) {
      console.error('JWT verify error (HS256):', err && err.message);
      return res.status(401).json({ message: 'Invalid token - verify failed', error: err && err.message });
    }
    console.log('JWT decoded (HS256):', decoded);
    req.user = decoded;
    next();
  });
}

// ========== AUTHENTICATION ENDPOINTS ==========

// Login (User)
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM users WHERE username = ?";

  db.query(sql, [username], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Login Failed", error: err });
    }

    const user = results[0];
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (password === user.password) {
      const payload = { id: user.id, username: user.username };
      const secret = process.env.JWT_SECRET || "change_this_secret";
      const token = jwt.sign(payload, secret, { expiresIn: "7d" });

      return res.json({
        success: true,
        message: "Login Success",
        user: { id: user.id, username: user.username, firstname: user.firstname, lastname: user.lastname,phone: user.phone, profile: user.profile_url || null },
        token: `${token}`
      });
    } else {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }
  });
});

// Register (User)
app.post("/api/register", (req, res) => {
  const { firstname, lastname, email, phone, username, password } = req.body;
  const sql = `
    INSERT INTO users 
    (firstname, lastname, email, phone, username, password) 
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [firstname, lastname, email, phone, username, password], (err, result) => {
    if (err) {
      console.error("=======================================");
      console.error(`[${new Date().toISOString()}] FATAL DB INSERT ERROR`);
      console.error("SQL Query:", sql.trim());
      console.error("Parameters:", [firstname, lastname, email, phone, username, password]);
      console.error("Error Details:", err);
      console.error("=======================================");

      return res.status(500).json({
        success: false,
        message: "Register Failed: Internal Server Error",
        error_code: err.code || "UNKNOWN_DB_ERROR"
      });
    }

    return res.json({ success: true, message: "Register Success", id: result.insertId });
  });
});

// Register Organizer
app.post("/reg/organizers", async (req, res) => {
  const {
    firstname,
    lastname,
    organizer_name,
    email,
    phone,
    username,
    password,
    organizer_type
  } = req.body;

  if (!firstname || !lastname || !organizer_name || !email || !username || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  if (!ALLOWED_TYPES.includes(organizer_type)) {
    return res.status(400).json({ message: "Invalid organizer_type" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters" });
  }

  try {
    const sql = `
      INSERT INTO organizer
      (firstname, lastname, organizer_name, email, phone, username, password, organizer_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [firstname, lastname, organizer_name, email, phone || null, username, password, organizer_type],
      (err, result) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Email or Username already exists" });
          }
          return res.status(500).json(err);
        }

        res.status(201).json({
          message: "Organizer created",
          organizer_id: result.insertId
        });
      }
    );
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login Organizer
app.post("/login/organizers", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing username or password" });
  }

  const sql = `SELECT * FROM organizer WHERE username = ? LIMIT 1`;
  db.query(sql, [username], async (err, rows) => {
    if (err) return res.status(500).json(err);
    if (!rows.length) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = rows[0];

    if (password !== user.password) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      {
        organizer_id: user.organizer_id,
        organizer_type: user.organizer_type
      },
      process.env.JWT_SECRET || "change_this_secret",
      { expiresIn: "7d" }
    );

    delete user.password;

    res.json({
      message: "Login success",
      token,
      user
    });
  });
});

// ========== USER ENDPOINTS ==========

app.get("/user/get-all", (req, res) => {
  const sql = "SELECT * FROM users";

  db.query(sql, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch users", error: err });
    }
    return res.json({ success: true, data: results });
  });
});

app.get("/user/get/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM users WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, data: results[0] });
  });
});

app.put("/user/update/:id", (req, res) => {
  const { id } = req.params;
  const { firstname, lastname, email, phone, username, password, profile_image } = req.body;

  if (!firstname && !lastname && !email && !phone && !username && !password && !profile_image) {
    return res.status(400).json({ success: false, message: "No fields provided for update" });
  }

  let sql = "UPDATE users SET ";
  const fields = [];
  const params = [];

  if (firstname) { fields.push("firstname = ?"); params.push(firstname); }
  if (lastname) { fields.push("lastname = ?"); params.push(lastname); }
  if (email) { fields.push("email = ?"); params.push(email); }
  if (phone) { fields.push("phone = ?"); params.push(phone); }
  if (username) { fields.push("username = ?"); params.push(username); }
  if (password) { fields.push("password = ?"); params.push(password); }
  if (profile_image) { fields.push("profile_image = ?"); params.push(profile_image); }

  sql += fields.join(", ") + " WHERE id = ?";
  params.push(id);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] DB UPDATE ERROR:`, err);
      return res.status(500).json({ success: false, message: "Update Failed: Internal Server Error", error_code: err.code || "UNKNOWN_DB_ERROR" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User Not Found" });
    }

    return res.json({ success: true, message: "Profile Updated Successfully" });
  });
});

app.put("/admin/user/:id", (req, res) => {
  const { id } = req.params;
  const { firstname, lastname, email, phone, username, password, profile_image } = req.body;

  if (!firstname && !lastname && !email && !phone && !username && !password && !profile_image) {
    return res.status(400).json({ success: false, message: "No fields provided for update" });
  }

  let sql = "UPDATE users SET ";
  const fields = [];
  const params = [];

  if (password && password.trim() !== '') { fields.push("password = ?"); params.push(password); }
  if (firstname) { fields.push("firstname = ?"); params.push(firstname); }
  if (lastname) { fields.push("lastname = ?"); params.push(lastname); }
  if (email) { fields.push("email = ?"); params.push(email); }
  if (phone) { fields.push("phone = ?"); params.push(phone); }
  if (username) { fields.push("username = ?"); params.push(username); }
  if (profile_image) { fields.push("profile_image = ?"); params.push(profile_image); }

  if (fields.length === 0) {
    return res.status(400).json({ success: false, message: "No fields provided for update" });
  }

  sql += fields.join(", ") + " WHERE id = ?";
  params.push(id);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] DB UPDATE ERROR:`, err);
      let errorMessage = "Database Error";
      let statusCode = 500;
      if (err.code === 'ER_DUP_ENTRY') {
        errorMessage = "Email or Username already exists.";
        statusCode = 409;
      }
      return res.status(statusCode).json({ success: false, message: errorMessage, error_code: err.code });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User Not Found" });
    }

    return res.json({ success: true, message: "Profile Updated Successfully" });
  });
});

app.delete("/user/delete/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM users WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, error: "Database error during deletion" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, message: "User Deleted Successfully", id });
  });
});

// ========== UNIVERSITY ENDPOINTS ==========

app.get("/university/get-all", (req, res) => {
  const sql = "SELECT * FROM un_data";

  db.query(sql, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }
    return res.json({ success: true, data: results });
  });
});

app.post("/university/search", (req, res) => {
  const { university_th, university_en, shortName, faculty, major, province } = req.body;

  let sql = "SELECT * FROM un_data WHERE 1=1";
  const params = [];

  if (university_th && university_th.trim()) { sql += " AND university_th LIKE ?"; params.push(`%${university_th}%`); }
  if (university_en && university_en.trim()) { sql += " AND university_en LIKE ?"; params.push(`%${university_en}%`); }
  if (shortName && shortName.trim()) { sql += " AND university_shortname LIKE ?"; params.push(`%${shortName}%`); }
  if (province && province.trim()) { sql += " AND province LIKE ?"; params.push(`%${province}%`); }
  if (faculty && faculty.trim()) { sql += " AND JSON_SEARCH(faculties, 'one', ?) IS NOT NULL"; params.push(faculty); }
  if (major && major.trim()) { sql += " AND JSON_SEARCH(majors, 'one', ?) IS NOT NULL"; params.push(major); }

  db.query(sql, params, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "No universities found", data: [] });
    }

    return res.json({ success: true, message: `Found ${results.length} result(s)`, data: results });
  });
});

app.get("/university/view/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM un_data WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Database Error", error: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "University not found" });
    }

    return res.json({ success: true, data: results[0] });
  });
});

app.post("/university/add", (req, res) => {
  const { university_th, university_en, university_shortname, university_type, province, website, logo, campuses, faculties, majors } = req.body;

  if (!university_th || !university_en || !university_shortname) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  const processField = (data, type) => {
    if (!data || !Array.isArray(data) || data.length === 0) return null;
    const processed = data
      .filter(item => {
        const nameField = type === "campuses" ? "campus_name" : type === "faculties" ? "faculty_name" : "major_name";
        return item[nameField] && item[nameField].trim();
      })
      .map((item, index) => {
        const nameField = type === "campuses" ? "campus_name" : type === "faculties" ? "faculty_name" : "major_name";
        return { id: index + 1, [nameField]: item[nameField].trim() };
      });
    return processed.length > 0 ? JSON.stringify(processed) : null;
  };

  const sql = `
    INSERT INTO un_data (university_th, university_en, university_shortname, university_type, province, website, logo, campuses, faculties, majors)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [university_th, university_en, university_shortname, university_type || null, province || null, website || null, logo || null, processField(campuses, "campuses"), processField(faculties, "faculties"), processField(majors, "majors")], (err, result) => {
    if (err) {
      console.error("❌ UNIVERSITY INSERT ERROR:", err);
      return res.status(500).json({ success: false, message: err.code === "ER_DUP_ENTRY" ? "University short name already exists" : "Insert failed", error: err.message });
    }
    return res.json({ success: true, message: "University added successfully", id: result.insertId });
  });
});

app.put("/university/edit/:id", (req, res) => {
  const { id } = req.params;
  const body = req.body;

  const allowedFields = ["university_th", "university_en", "university_shortname", "university_type", "province", "website", "logo", "campuses", "faculties", "majors"];

  let sqlParts = [];
  let params = [];

  allowedFields.forEach(field => {
    if (body.hasOwnProperty(field)) {
      let value = body[field];
      if (typeof value === "object" && value !== null) value = JSON.stringify(value);
      sqlParts.push(`${field} = ?`);
      params.push(value);
    }
  });

  if (sqlParts.length === 0) {
    return res.status(400).json({ success: false, message: "No valid fields provided for update" });
  }

  const sql = `UPDATE un_data SET ${sqlParts.join(", ")} WHERE id = ?`;
  params.push(id);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("❌ DB UPDATE ERROR:", err);
      return res.status(500).json({ success: false, message: "Update Failed", error: err });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "University not found" });
    }

    return res.json({ success: true, message: "University Updated Successfully" });
  });
});

app.delete("/university/delete/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM un_data WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, error: "Database error during deletion" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "University not found" });
    }

    return res.json({ success: true, message: "University Deleted Successfully", id });
  });
});

// ========== EVENT ENDPOINTS ==========

app.get("/event/get", (req, res) => {
  const sql = `
    SELECT activity_id, organizer_id, organizer_name, title, description, location, open_date, close_date, image_url, contact1, contact2, status
    FROM event
    ORDER BY organizer_id, open_date
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error fetching events:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch events" });
    }

    const organizersMap = {};
    results.forEach(row => {
      if (!organizersMap[row.organizer_id]) {
        organizersMap[row.organizer_id] = { organizer_id: row.organizer_id, organizer_name: row.organizer_name, activities: [] };
      }
      organizersMap[row.organizer_id].activities.push({
        activity_id: row.activity_id, title: row.title, description: row.description, location: row.location,
        open_date: row.open_date, close_date: row.close_date, image_url: row.image_url,
        contact1: row.contact1, contact2: row.contact2, status: row.status
      });
    });

    res.json({ success: true, data: Object.values(organizersMap) });
  });
});

app.get("/event/get/:id", (req, res) => {
  const { id } = req.params;

  if (!id) return res.status(400).json({ success: false, message: "Event ID is required" });

  const sql = "SELECT * FROM event WHERE activity_id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }

    if (results.length === 0) return res.status(404).json({ success: false, message: "Event not found" });

    return res.json({ success: true, data: results[0] });
  });
});

app.get("/event/organizer/:organizerId", (req, res) => {
  const { organizerId } = req.params;

  if (!organizerId) return res.status(400).json({ success: false, message: "Organizer ID is required" });

  const sql = "SELECT * FROM event WHERE organizer_id = ?";

  db.query(sql, [organizerId], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }

    return res.json({ success: true, data: results, count: results.length });
  });
});

app.get("/getall/event/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM event WHERE organizer_id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching event:", err);
      return res.status(500).json({ message: "Failed to fetch event" });
    }
    if (results.length === 0) return res.status(404).json({ message: "Event not found" });
    res.json(results);
  });
});

// Create event
app.post("/post/event", verifyToken, upload.single('image'), (req, res) => {
  const { organizer_id, organizer_name, title, description, location, open_date, close_date, contact1, contact2, status } = req.body;

  if (!organizer_id || !organizer_name || !title || !description || !location || !open_date || !close_date || !contact1) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const toMySQL = (isoStr) => new Date(isoStr).toISOString().slice(0, 19).replace('T', ' ');
  const formattedOpenDate = toMySQL(open_date);
  const formattedCloseDate = toMySQL(close_date);

  if (new Date(formattedCloseDate) <= new Date(formattedOpenDate)) {
    return res.status(400).json({ message: "Close date must be after open date" });
  }

  let image_url = null;
  if (req.file) {
    image_url = uploadFileLocal(req.file, 'event');
  }

  const getLastIdSQL = `SELECT activity_id FROM event ORDER BY activity_id DESC LIMIT 1`;

  db.query(getLastIdSQL, (err, rows) => {
    if (err) return res.status(500).json(err);

    let newActivityId = "ACT000001";
    if (rows.length) {
      const lastId = rows[0].activity_id;
      const number = parseInt(lastId.replace("ACT", ""));
      newActivityId = `ACT${String(number + 1).padStart(6, "0")}`;
    }
    // ✅ รับทั้ง Thai และ English แล้วแปลงเป็น English ก่อน insert
    const statusMap = {
      'เปิดรับ': 'open',
      'ใกล้เต็ม': 'almost_full',
      'open': 'open',
      'almost_full': 'almost_full'
    };

    const mappedStatus = statusMap[status];
    if (!mappedStatus) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const insertSQL = `
      INSERT INTO event (
        activity_id, organizer_id, organizer_name, title, description,
        location, open_date, close_date, image_url, contact1, contact2, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(insertSQL, [newActivityId, organizer_id, organizer_name, title, description, location, formattedOpenDate, formattedCloseDate, image_url || null, contact1, contact2 || null, mappedStatus], (err) => {
      if (err) {
        console.error('❌ Insert event error:', err);
        return res.status(500).json({ message: 'Failed to insert event', error: err });
      }

      res.status(201).json({ message: "Event created successfully", activity_id: newActivityId, image_url });
    });
  });
});

app.put("/event/edit/:id", upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { activity_id, title, description, location, open_date, close_date, status, organizer_id, organizer_name } = req.body;

  if (!id || !activity_id || !title) {
    return res.status(400).json({ success: false, message: "Missing required fields: id, activity_id, title" });
  }

  let image = null;
  if (req.file) image = uploadFileLocal(req.file, 'event');

  const sql = `
    UPDATE event 
    SET activity_id = ?, title = ?, description = ?, location = ?, open_date = ?, close_date = ?, status = ?,
    ${image ? 'image_url = ?,' : ''}
    organizer_id = ?, organizer_name = ?
    WHERE id = ?
  `;

  const params = image
    ? [activity_id, title, description || null, location || null, open_date || null, close_date || null, status || null, image, organizer_id || null, organizer_name || null, id]
    : [activity_id, title, description || null, location || null, open_date || null, close_date || null, status || null, organizer_id || null, organizer_name || null, id];

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("❌ UPDATE EVENT ERROR:", err);
      return res.status(500).json({ success: false, message: "Update failed", error: err.message });
    }

    if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Event not found" });

    return res.json({ success: true, message: "Event updated successfully", id });
  });
});

app.delete("/event/delete/:id", (req, res) => {
  const { id } = req.params;

  if (!id) return res.status(400).json({ success: false, message: "Event ID is required" });

  const sql = "DELETE FROM event WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("❌ DELETE EVENT ERROR:", err);
      return res.status(500).json({ success: false, message: "Delete failed", error: err.message });
    }

    if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Event not found" });

    return res.json({ success: true, message: "Event deleted successfully", deletedRows: result.affectedRows });
  });
});

app.post("/register-event", (req, res) => {
  const { activity_id, organizer_name, firstname, lastname, phone } = req.body;

  if (!activity_id || !firstname || !lastname || !phone) {
    return res.status(400).json({ success: false, message: "ข้อมูลไม่ครบ" });
  }

  const sql = `INSERT INTO register_event (activity_id, organizer_name, firstname, lastname, phone) VALUES (?, ?, ?, ?, ?)`;

  db.query(sql, [activity_id, organizer_name, firstname, lastname, phone], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "บันทึกข้อมูลไม่สำเร็จ" });
    }

    res.status(201).json({ success: true, message: "ลงทะเบียนสำเร็จ", register_id: result.insertId });
  });
});

// ========== TABLE INFO ENDPOINTS ==========

app.get("/table/get", (req, res) => {
  const sql = `
    SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ENGINE, VERSION, ROW_FORMAT, TABLE_ROWS,
    AVG_ROW_LENGTH, DATA_LENGTH, MAX_DATA_LENGTH, INDEX_LENGTH, DATA_FREE, AUTO_INCREMENT, CREATE_TIME,
    UPDATE_TIME, CHECK_TIME, TABLE_COLLATION, CHECKSUM, CREATE_OPTIONS, TABLE_COMMENT
    FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ GET TABLES ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch tables", error: err.message });
    }
    return res.json({ success: true, data: results, count: results.length });
  });
});

app.get("/table/:tableName", (req, res) => {
  const { tableName } = req.params;
  if (!tableName) return res.status(400).json({ success: false, message: "Table name is required" });

  const sql = `
    SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ENGINE, VERSION, ROW_FORMAT, TABLE_ROWS,
    AVG_ROW_LENGTH, DATA_LENGTH, MAX_DATA_LENGTH, INDEX_LENGTH, DATA_FREE, AUTO_INCREMENT, CREATE_TIME,
    UPDATE_TIME, CHECK_TIME, TABLE_COLLATION, CHECKSUM, CREATE_OPTIONS, TABLE_COMMENT
    FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET TABLE ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch table", error: err.message });
    }
    if (results.length === 0) return res.status(404).json({ success: false, message: `Table '${tableName}' not found` });
    return res.json({ success: true, data: results[0] });
  });
});

app.get("/table/:tableName/columns", (req, res) => {
  const { tableName } = req.params;
  if (!tableName) return res.status(400).json({ success: false, message: "Table name is required" });

  const sql = `
    SELECT COLUMN_NAME, ORDINAL_POSITION, COLUMN_DEFAULT, IS_NULLABLE, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH,
    NUMERIC_PRECISION, NUMERIC_SCALE, COLUMN_KEY, EXTRA, COLUMN_COMMENT
    FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET COLUMNS ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch columns", error: err.message });
    }
    return res.json({ success: true, data: results, count: results.length });
  });
});

app.get("/table/:tableName/size", (req, res) => {
  const { tableName } = req.params;
  if (!tableName) return res.status(400).json({ success: false, message: "Table name is required" });

  const sql = `
    SELECT TABLE_NAME, ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
    TABLE_ROWS, ROUND((data_length / TABLE_ROWS), 2) AS avg_row_size_bytes
    FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET TABLE SIZE ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch table size", error: err.message });
    }
    if (results.length === 0) return res.status(404).json({ success: false, message: `Table '${tableName}' not found` });
    return res.json({ success: true, data: results[0] });
  });
});

app.get("/tables/size/all", (req, res) => {
  const sql = `
    SELECT TABLE_NAME, ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
    TABLE_ROWS, ROUND((data_length / TABLE_ROWS), 2) AS avg_row_size_bytes
    FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY (data_length + index_length) DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ GET ALL TABLES SIZE ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch tables size", error: err.message });
    }
    return res.json({ success: true, data: results, count: results.length });
  });
});

// ================= CREATE PORTFOLIO =================

const saveFileToCPanel = (file, subfolder) => {
  if (!file) return null;

  const targetDir = path.join(__dirname, '../public_html/api.dailylifes.online/uploads', subfolder);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const fileName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
  const filePath = path.join(targetDir, fileName);
  fs.writeFileSync(filePath, file.buffer);

  return `/uploads/${subfolder}/${fileName}`;
};

app.post("/createport", verifyToken, upload.any(), async (req, res) => {
  console.log("=== FIELDS ===", req.files?.map(f => f.fieldname));
  console.log("=== BODY KEYS ===", Object.keys(req.body));

  const connection = await db.promise().getConnection();

  try {
    await connection.beginTransaction();

    let parsedBody = req.body;
    if (typeof req.body.data === 'string') parsedBody = JSON.parse(req.body.data);

    const { user_id, port_id, personal_info, educational, skills_abilities, activities_certificates, university_choice } = parsedBody;

    if (!user_id || !port_id) throw new Error("Missing user_id or port_id");

    const files = req.files || [];
    const profileFile = files.find(f => f.fieldname === 'profile');
    const transcriptFile = files.find(f => f.fieldname === 'transcript');
    const certFiles = files.filter(f => f.fieldname === 'certificate');

    let profileUrl = profileFile ? saveFileToCPanel(profileFile, 'profile') : null;
    let transcriptUrl = transcriptFile ? saveFileToCPanel(transcriptFile, 'transcript') : null;
    let certificateUrls = certFiles.map(f => saveFileToCPanel(f, 'certificates'));

    await connection.query(`INSERT INTO portfolios (user_id, port_id, profile_url) VALUES (?, ?, ?)`, [user_id, port_id, profileUrl]);

    if (personal_info) {
      await connection.query(
        `INSERT INTO personal_info (port_id, portfolio_name, introduce, prefix, first_name, last_name, date_birth, nationality, national_id, phone_number1, phone_number2, email, address, province, district, subdistrict, postal_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [port_id, personal_info.portfolio_name, personal_info.introduce, personal_info.prefix, personal_info.first_name, personal_info.last_name, personal_info.date_birth, personal_info.nationality, personal_info.national_id, personal_info.phone_number1, personal_info.phone_number2, personal_info.email, personal_info.address, personal_info.province, personal_info.district, personal_info.subdistrict, personal_info.postal_code]
      );
    }

    if (Array.isArray(educational)) {
      for (const edu of educational) {
        await connection.query(
          `INSERT INTO educational (port_id, number, school, graduation, educational_qualifications, province, district, study_path, grade_average, study_results) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [port_id, edu.number, edu.school, edu.graduation, edu.educational_qualifications, edu.province, edu.district, edu.study_path, edu.grade_average, transcriptUrl]
        );
      }
    }

    if (skills_abilities) {
      const [skillRes] = await connection.query(`INSERT INTO skills_abilities (port_id, details) VALUES (?, ?)`, [port_id, skills_abilities.details]);
      const skillsId = skillRes.insertId;

      if (Array.isArray(skills_abilities.language_skills)) {
        for (const lang of skills_abilities.language_skills) {
          await connection.query(
            `INSERT INTO language_skills (port_id, skills_abilities_id, language, listening, speaking, reading, writing) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [port_id, skillsId, lang.language, lang.listening, lang.speaking, lang.reading, lang.writing]
          );
        }
      }
    }

    if (Array.isArray(activities_certificates)) {
      for (const activity of activities_certificates) {
        await connection.query(
          `INSERT INTO activities_certificates (port_id, number, name_project, date, photo, details) VALUES (?, ?, ?, ?, ?, ?)`,
          [port_id, activity.number, activity.name_project, activity.date, JSON.stringify(certificateUrls), activity.details]
        );
      }
    }

    if (Array.isArray(university_choice)) {
      for (const uni of university_choice) {
        await connection.query(
          `INSERT INTO university_choice (port_id, university, faculty, major, details) VALUES (?, ?, ?, ?, ?)`,
          [port_id, uni.university, uni.faculty, uni.major, uni.details]
        );
      }
    }

    await connection.commit();

    res.status(200).json({ success: true, message: "สร้าง Portfolio และอัปโหลดไฟล์เรียบร้อยแล้ว", data: { profile: profileUrl, transcript: transcriptUrl, certificates: certificateUrls } });

  } catch (err) {
    await connection.rollback();
    console.error("❌ Create Portfolio Error:", err);
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการสร้าง Portfolio", error: err.message });
  } finally {
    connection.release();
  }
});

// ================= UPDATE PORTFOLIO =================

app.put("/updateport/:port_id", verifyToken, upload.any(), async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "port_id required" });

  const connection = await db.promise().getConnection();

  try {
    await connection.beginTransaction();

    let parsedBody = req.body;
    if (typeof req.body.data === 'string') parsedBody = JSON.parse(req.body.data);

    const { personal_info, educational, skills_abilities, activities_certificates, university_choice } = parsedBody;

    const files = req.files || [];
    const profileFile = files.find(f => f.fieldname === 'profile');
    const transcriptFile = files.find(f => f.fieldname === 'transcript');
    const certFiles = files.filter(f => f.fieldname === 'certificate');

    // ===== Update profile image if new one uploaded =====
    if (profileFile) {
      const profileUrl = saveFileToCPanel(profileFile, 'profile');
      await connection.query(`UPDATE portfolios SET profile_url = ? WHERE port_id = ?`, [profileUrl, port_id]);
    } else if (personal_info?.profile_image_url) {
      await connection.query(`UPDATE portfolios SET profile_url = ? WHERE port_id = ?`, [personal_info.profile_image_url, port_id]);
    }

    // ===== Update personal_info =====
    if (personal_info) {
      const [existing] = await connection.query(`SELECT port_id FROM personal_info WHERE port_id = ?`, [port_id]);
      if (existing.length > 0) {
        await connection.query(
          `UPDATE personal_info SET portfolio_name=?, introduce=?, prefix=?, first_name=?, last_name=?, date_birth=?, nationality=?, national_id=?, phone_number1=?, phone_number2=?, email=?, address=?, province=?, district=?, subdistrict=?, postal_code=? WHERE port_id=?`,
          [personal_info.portfolio_name, personal_info.introduce, personal_info.prefix, personal_info.first_name, personal_info.last_name, personal_info.date_birth, personal_info.nationality, personal_info.national_id, personal_info.phone_number1, personal_info.phone_number2, personal_info.email, personal_info.address, personal_info.province, personal_info.district, personal_info.subdistrict, personal_info.postal_code, port_id]
        );
      } else {
        await connection.query(
          `INSERT INTO personal_info (port_id, portfolio_name, introduce, prefix, first_name, last_name, date_birth, nationality, national_id, phone_number1, phone_number2, email, address, province, district, subdistrict, postal_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [port_id, personal_info.portfolio_name, personal_info.introduce, personal_info.prefix, personal_info.first_name, personal_info.last_name, personal_info.date_birth, personal_info.nationality, personal_info.national_id, personal_info.phone_number1, personal_info.phone_number2, personal_info.email, personal_info.address, personal_info.province, personal_info.district, personal_info.subdistrict, personal_info.postal_code]
        );
      }
    }

    // ===== Update educational (delete + re-insert) =====
    if (Array.isArray(educational)) {
      await connection.query(`DELETE FROM educational WHERE port_id = ?`, [port_id]);
      const transcriptUrl = transcriptFile ? saveFileToCPanel(transcriptFile, 'transcript') : null;
      for (const edu of educational) {
        const studyResults = transcriptUrl || (typeof edu.study_results === 'string' ? edu.study_results : null);
        await connection.query(
          `INSERT INTO educational (port_id, number, school, graduation, educational_qualifications, province, district, study_path, grade_average, study_results) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [port_id, edu.number, edu.school, edu.graduation, edu.educational_qualifications, edu.province, edu.district, edu.study_path, edu.grade_average, studyResults]
        );
      }
    }

    // ===== Update skills_abilities (delete + re-insert) =====
    if (skills_abilities) {
      await connection.query(`DELETE FROM language_skills WHERE port_id = ?`, [port_id]);
      await connection.query(`DELETE FROM skills_abilities WHERE port_id = ?`, [port_id]);

      const [skillRes] = await connection.query(
        `INSERT INTO skills_abilities (port_id, details, others) VALUES (?, ?, ?)`,
        [port_id, skills_abilities.details, skills_abilities.others || null]
      );
      const skillsId = skillRes.insertId;

      if (Array.isArray(skills_abilities.language_skills)) {
        for (const lang of skills_abilities.language_skills) {
          if (!lang.language) continue;
          await connection.query(
            `INSERT INTO language_skills (port_id, skills_abilities_id, language, listening, speaking, reading, writing) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [port_id, skillsId, lang.language, lang.listening, lang.speaking, lang.reading, lang.writing]
          );
        }
      }
    }

    // ===== Update activities_certificates (delete + re-insert) =====
    if (Array.isArray(activities_certificates)) {
      await connection.query(`DELETE FROM activities_certificates WHERE port_id = ?`, [port_id]);
      const certUrls = certFiles.map(f => saveFileToCPanel(f, 'certificates'));
      let certUrlIndex = 0;
      for (const activity of activities_certificates) {
        // Use newly uploaded file URL, or existing photo_url string, or null
        let photoUrl = null;
        if (certUrls[certUrlIndex]) {
          photoUrl = certUrls[certUrlIndex++];
        } else if (typeof activity.photo === 'string') {
          photoUrl = activity.photo;
        } else if (typeof activity.photo_url === 'string') {
          photoUrl = activity.photo_url;
        }
        await connection.query(
          `INSERT INTO activities_certificates (port_id, number, name_project, date, photo, details) VALUES (?, ?, ?, ?, ?, ?)`,
          [port_id, activity.number, activity.name_project, activity.date, photoUrl, activity.details]
        );
      }
    }

    // ===== Update university_choice (delete + re-insert) =====
    if (Array.isArray(university_choice)) {
      await connection.query(`DELETE FROM university_choice WHERE port_id = ?`, [port_id]);
      for (const uni of university_choice) {
        await connection.query(
          `INSERT INTO university_choice (port_id, university, faculty, major, details) VALUES (?, ?, ?, ?, ?)`,
          [port_id, uni.university, uni.faculty, uni.major, uni.details]
        );
      }
    }

    await connection.commit();
    res.status(200).json({ success: true, message: "อัปเดต Portfolio เรียบร้อยแล้ว" });

  } catch (err) {
    await connection.rollback();
    console.error("❌ Update Portfolio Error:", err);
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการอัปเดต Portfolio", error: err.message });
  } finally {
    connection.release();
  }
});

app.get("/getport/:userid", async (req, res) => {
  const { userid } = req.params;
  if (!userid) return res.status(400).json({ success: false, message: "User id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT port_id, profile_url FROM Daily_Life_DB.portfolios WHERE user_id = ?", [userid]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", user_id: userid, portfolio_count: 0, data: [] });

    return res.json({ success: true, user_id: userid, portfolio_count: ports.length, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getpersonal_info/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT portfolio_name, introduce, prefix, first_name, last_name, date_birth, nationality, national_id, phone_number1, phone_number2, email, address, province, district, subdistrict, postal_code FROM Daily_Life_DB.personal_info WHERE port_id = ?", [port_id]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", port_id, data: [] });

    return res.json({ success: true, port_id, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/geteducational/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT `number`, school, graduation, educational_qualifications, province, district, study_path, grade_average, study_results FROM Daily_Life_DB.educational WHERE port_id = ?", [port_id]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", port_id, data: [] });

    return res.json({ success: true, port_id, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getskills_abilities/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT s.id, s.port_id, s.details, l.skills_abilities_id, l.language, l.listening, l.speaking, l.reading, l.writing FROM Daily_Life_DB.skills_abilities s LEFT JOIN Daily_Life_DB.language_skills l ON s.id = l.skills_abilities_id WHERE s.port_id = ?", [port_id]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", port_id, data: [] });

    return res.json({ success: true, port_id, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getactivities_certificates/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT id, port_id, `number`, name_project, `date`, photo, details FROM Daily_Life_DB.activities_certificates WHERE port_id = ?", [port_id]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", port_id, data: [] });

    return res.json({ success: true, port_id, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getuniversity_choice/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();
    const [ports] = await pool.query("SELECT id, port_id, university, faculty, major, details FROM Daily_Life_DB.university_choice WHERE port_id = ?", [port_id]);

    if (!ports || ports.length === 0) return res.json({ pulldata: "success", port_id, data: [] });

    return res.json({ success: true, port_id, data: ports });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

// ========== LOCAL FILE UPLOAD ENDPOINTS ==========

app.post('/upload/event-image', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const imageUrl = await uploadFileLocal(req.file, 'event');
    return res.json({ imageUrl });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ message: 'Failed to upload file', error: err.message });
  }
});

app.post('/upload/transcript', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const imageUrl = uploadFileLocal(req.file, 'transcript');
    return res.json({ imageUrl });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ message: 'Failed to upload file', error: err.message });
  }
});

app.post('/upload/profile', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const imageUrl = uploadFileLocal(req.file, 'profile');
    return res.json({ imageUrl });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ message: 'Failed to upload file', error: err.message });
  }
});

app.post('/upload/certificate', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const imageUrl = uploadFileLocal(req.file, 'certificates');
    return res.json({ imageUrl });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ message: 'Failed to upload file', error: err.message });
  }
});

// ========== API ลงทะเบียนเข้าร่วมกิจกรรม ==========
app.post('/event/register', (req, res) => {
  const { activity_id, organizer_name, firstname, lastname, phone } = req.body;

  // 1. ตรวจสอบว่ามีค่าว่างหรือไม่ (รวมถึงการเช็ค string ว่างด้วย)
  if (!activity_id || !firstname || !lastname || !phone || phone.trim() === "") {
    return res.status(400).json({ 
      message: "กรุณากรอกข้อมูลให้ครบถ้วน (activity_id, firstname, lastname, phone)" 
    });
  }

  // 2. ใช้ SQL INSERT
  const sql = "INSERT INTO register_event (activity_id, organizer_name, firstname, lastname, phone) VALUES (?, ?, ?, ?, ?)";
  
  db.query(sql, [activity_id, organizer_name, firstname, lastname, phone], (err, result) => {
    if (err) {
      console.error("SQL Error:", err);
      
      // กรณี Error เรื่องภาษาไทย (ถ้ายังไม่ได้แก้ Character Set)
      if (err.errno === 1064 || err.code === 'ER_PARSE_ERROR') {
         return res.status(500).json({ message: "Database syntax error (Check Thai encoding)" });
      }

      // กรณี Foreign Key Error (ไม่มี activity_id นี้ในตาราง event)
      if (err.code === 'ER_NO_REFERENCED_ROW_2') {
        return res.status(400).json({ message: "ไม่พบรหัสกิจกรรมนี้ในระบบ" });
      }

      return res.status(500).json({ message: "เกิดข้อผิดพลาดในระบบฐานข้อมูล", error: err.message });
    }

    res.status(201).json({ 
      message: "ลงทะเบียนสำเร็จ 🎉", 
      id: result.insertId 
    });
  });
});

// ========== ERROR HANDLING ==========

app.use((err, req, res, next) => {
  if (err && err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ message: 'File too large. Max size is 20MB.' });
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

// ========== START SERVER ==========
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
  console.log(`📁 Upload directory: ${uploadDirs.profile}`);
});