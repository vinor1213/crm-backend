require('dotenv').config();
require('ts-node/register');
const app = require('./src/app').default;

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
