(function () {
  function attachTerminal(el, socket) {
    let buffer = "";
    el.setAttribute("contenteditable", "true");

    socket.on("term_data", (chunk) => {
      buffer += chunk;
      el.textContent = buffer;
      el.scrollTop = el.scrollHeight;
    });

    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { socket.emit("term_input", "\r"); e.preventDefault(); return; }
      if (e.key === "Backspace") { socket.emit("term_input", "\x7f"); e.preventDefault(); return; }
      if (e.key === "Tab") { socket.emit("term_input", "\t"); e.preventDefault(); return; }
      if (e.key === "ArrowUp") { socket.emit("term_input", "\x1b[A"); e.preventDefault(); return; }
      if (e.key === "ArrowDown") { socket.emit("term_input", "\x1b[B"); e.preventDefault(); return; }
      if (e.key === "ArrowRight") { socket.emit("term_input", "\x1b[C"); e.preventDefault(); return; }
      if (e.key === "ArrowLeft") { socket.emit("term_input", "\x1b[D"); e.preventDefault(); return; }
      if (e.ctrlKey && e.key.toLowerCase() === "c") { socket.emit("term_input", "\x03"); e.preventDefault(); return; }
      if (e.ctrlKey && e.key.toLowerCase() === "d") { socket.emit("term_input", "\x04"); e.preventDefault(); return; }
      if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) { socket.emit("term_input", e.key); e.preventDefault(); }
    });

    const ro = new ResizeObserver(() => {
      const cols = Math.max(40, Math.floor(el.clientWidth / 8));
      const rows = Math.max(10, Math.floor(el.clientHeight / 18));
      socket.emit("term_resize", { cols, rows });
    });
    ro.observe(el);

    setTimeout(() => el.focus(), 50);
  }

  window.initAdminTerminal = function () {
    const socket = io("/admin-term");
    const el = document.getElementById("admin-terminal");
    attachTerminal(el, socket);
  };
})();
