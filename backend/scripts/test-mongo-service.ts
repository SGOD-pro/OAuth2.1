import {
  startSharedMongo,
  stopSharedMongo,
  isHarnessRunning,
  isDockerContainerRunning,
  getHarnessPort,
  getBaseAdminUri,
  CONTAINER_NAME,
} from "../tests/fixtures/test-docker-mongo";

const action = process.argv[2] || "status";

async function main() {
  const port = getHarnessPort();

  if (action === "start") {
    console.log(`Starting shared test MongoDB container (${CONTAINER_NAME}) on 127.0.0.1:${port}...`);
    const { port: actualPort, uri } = await startSharedMongo();
    console.log(`[READY] Shared test MongoDB container running on port ${actualPort}`);
    console.log(`URI: ${uri}`);
  } else if (action === "stop") {
    console.log(`Stopping shared test MongoDB container (${CONTAINER_NAME})...`);
    stopSharedMongo();
    console.log(`[STOPPED] Shared test MongoDB container stopped.`);
  } else if (action === "status") {
    const running = isDockerContainerRunning();
    const ready = await isHarnessRunning(port);
    console.log(`Container running: ${running}`);
    console.log(`Replica set primary ready: ${ready}`);
    console.log(`Port: ${port}`);
    console.log(`Base Admin URI: ${getBaseAdminUri(port)}`);
    if (!ready) {
      process.exitCode = 1;
    }
  } else {
    console.error(`Unknown action: ${action}. Use start, stop, or status.`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("Command failed:", err?.message || err);
  process.exit(1);
});
