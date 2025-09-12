# Webterm

A **browser-based terminal** with authentication, admin/user roles, and real-time shell access.  
Built with **Node.js, Express, SQLite, Socket.IO, and Firebase OAuth (Google/GitHub/Email)**.

---

## ✨ Features

- 🔐 **Authentication**
  - Register/Login with username + password
  - Firebase OAuth (Google, GitHub, Email/Password)
  - Admin vs User roles
- 🖥️ **Web Terminal**
  - Real-time command execution with xterm.js + Socket.IO
  - Command input, output, and history
  - Clear and copy controls
- ⚙️ **Admin Dashboard**
  - Manage users
  - Track activity
  - Audit logs
- 🌐 **Cross-Platform**
  - Works in browser
  - Optional mobile/desktop builds (PWA, Android artifacts included)

---

## 📂 Project Structure

```
Webterminal/
├── server.js            # Main server
├── db.js                # Database logic (SQLite)
├── userStatus.js        # User status tracking
├── adminStore.js        # Admin logic
├── boxService.js        # Terminal service
├── firebase.js          # Firebase auth integration
├── public/              # Static assets (JS/CSS)
├── views/               # EJS templates (login, register, terminal, etc.)
├── data/                # App data
├── workspaces/          # User workspaces
├── database.sqlite      # Main DB
├── users.db             # User DB
└── README.md
```

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone git@github.com:nekoCd/Webterm.git
cd Webterm/webterminal
```

### 2. Install dependencies
```bash
npm install
```

### 3. Run the app
```bash
npm start
```

By default the app runs at:  
👉 `http://localhost:3000`  

---

## 🔑 Configuration

Set up a `.env` file in `/webterminal`:

```env
PORT=443
SESSION_SECRET=your-secret-key
DATABASE_URL=./database.sqlite

# Firebase config
FIREBASE_API_KEY=your-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-project.appspot.com
FIREBASE_MESSAGING_SENDER_ID=your-sender-id
FIREBASE_APP_ID=your-app-id
```

---

## 🛡️ Security

- Passwords hashed with **bcrypt**
- Sessions secured with **express-session**
- Optional **JWT** auth support
- Input validation + rate limiting
- Audit logging for terminal activity

---

## 🧑‍💻 Development

- **Frontend**: EJS + TailwindCSS (customizable)
- **Backend**: Node.js (Express + Socket.IO)
- **Database**: SQLite (simple + portable)
- **Auth**: Firebase (Google/GitHub/Email) + Local DB

---

## 📦 Deployment

### Docker (recommended)
```bash
docker build -t webterm .
docker run -p 443:443 webterm
```

### Manual
- Run on Linux/macOS/Windows with Node.js LTS
- Use reverse proxy (Nginx/Apache) for HTTPS

---

## 👤 Author

**Adam Lee Kinville**

---

## 📜 License

MIT License – free to use, modify, and distribute.
