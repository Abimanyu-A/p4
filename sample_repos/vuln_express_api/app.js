const express = require("express");
const app = express();
app.use(express.json());
app.use("/", require("./routes/orders"));

if (require.main === module) {
  app.listen(3000, () => console.log("vuln-express-api listening on :3000"));
}

module.exports = app;
