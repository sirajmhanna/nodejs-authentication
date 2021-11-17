const http = require("http");
const app = require("./app");
const port = process.env.PORT || 5000;
const logger = require("./helpers/winston");

const server = http.createServer(app);
server.listen(port, () => {
  logger.info(new Date().getTime(), "server", "listen", `Server is up`, {
    port,
  });
});
