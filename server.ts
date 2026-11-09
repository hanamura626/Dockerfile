import { createServer, IncomingMessage, ServerResponse } from "node:http";

const PORT = Number(process.env.PORT) || 3000;

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const path = new URL(req.url || "/", "http://x").pathname;
  if (path === "/") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("server is running");
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

server.listen(PORT, () => {
  console.log(`✅ Server berjalan di http://localhost:${PORT}`);
});
