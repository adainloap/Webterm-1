(function () {
  const socket = io("/events");

  // Listen for login events
  socket.on("login_event", (event) => {
    const feed = document.getElementById("login-feed");
    const li = document.createElement("li");
    const when = new Date(event.time).toLocaleString();
    li.innerHTML = `<strong>${event.type === "admin" ? "Admin" : "User"} login</strong> — <code>${event.username}</code> from <code>${event.ip}</code> @ ${when}`;
    feed.prepend(li);
  });
})();
