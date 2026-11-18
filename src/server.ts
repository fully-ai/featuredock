import { createFeatureDockApp } from "./app.js";

const host = process.env.FEATUREDOCK_HOST ?? "127.0.0.1";
const port = Number(process.env.FEATUREDOCK_PORT ?? 8096);

const { app } = createFeatureDockApp();
app.listen(port, host, () => {
  console.log(`FeatureDock listening on http://${host}:${port}`);
});
