// userStatus.js
const onlineUsers = new Set();

/**
 * Marks a user as online
 * @param {string} username
 */
export function setOnline(username) {
  onlineUsers.add(username);
}

/**
 * Marks a user as offline
 * @param {string} username
 */
export function setOffline(username) {
  onlineUsers.delete(username);
}

/**
 * Checks if a user is online
 * @param {string} username
 * @returns {boolean}
 */
export function isOnline(username) {
  return onlineUsers.has(username);
}

/**
 * Returns all online users
 * @returns {string[]}
 */
export function getOnlineUsers() {
  return Array.from(onlineUsers);
}
