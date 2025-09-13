import bcrypt from 'bcryptjs';
import { EOL } from 'os';

// The password you want to use for the admin account.
// You can change this to whatever you want.
const password = '1e+2901e+290'; 

const saltRounds = 10;
const hashedPassword = bcrypt.hashSync(password, saltRounds);

console.log('--- Copy this hash into your server.js file ---');
console.log(hashedPassword);
console.log('----------------------------------------------' + EOL);