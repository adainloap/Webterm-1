import { ioInstance } from './server.js';

ioInstance.on('connection', (socket) => {
  socket.on('custom_event', (data) => {
    console.log('Received custom_event:', data);
  });
});
