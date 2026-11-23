import { ChildProcess } from "node:child_process";

export interface SendWorkerMessageOptions {
  stage?: string;
  expectedType?: string;
  timeoutMs?: number;
}

export function sendToWorker<T = any>(
  child: ChildProcess,
  msg: Record<string, any>,
  options: SendWorkerMessageOptions = {}
): Promise<T> {
  const stage = options.stage || msg?.type || "unknown stage";
  const timeoutMs = options.timeoutMs ?? 5000;
  const expectedType = options.expectedType;

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let timer: NodeJS.Timeout | null = null;

    const cleanup = () => {
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("disconnect", onDisconnect);
    };

    const onMessage = (res: any) => {
      if (!res || typeof res !== "object") return;
      if (res.type === "ERROR") {
        cleanup();
        reject(new Error(`Worker error during stage "${stage}": ${res.error || "unknown worker error"}`));
        return;
      }
      if (expectedType && res.type !== expectedType) {
        return;
      }
      cleanup();
      resolve(res);
    };

    const onError = (err: Error) => {
      cleanup();
      reject(new Error(`Worker emitted error during stage "${stage}": ${err?.message || String(err)}`));
    };

    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(new Error(`Worker exited during stage "${stage}" with code ${code} and signal ${signal}`));
    };

    const onDisconnect = () => {
      cleanup();
      reject(new Error(`Worker disconnected during stage "${stage}"`));
    };

    child.on("message", onMessage);
    child.on("error", onError);
    child.on("exit", onExit);
    child.on("disconnect", onDisconnect);

    timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Worker request timed out after ${timeoutMs}ms during stage "${stage}"`));
    }, timeoutMs);

    child.send(msg, (err) => {
      if (err && !settled) {
        cleanup();
        reject(new Error(`Failed to send message to worker during stage "${stage}": ${err.message}`));
      }
    });
  });
}

export async function waitForWorkerEvent<T = any>(
  child: ChildProcess,
  eventType: string,
  stage: string,
  timeoutMs = 5000
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let timer: NodeJS.Timeout | null = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("disconnect", onDisconnect);
    };

    const onMessage = (msg: any) => {
      if (!msg || typeof msg !== "object") return;
      if (msg.type === "ERROR") {
        cleanup();
        reject(new Error(`Worker error waiting for "${eventType}" in stage "${stage}": ${msg.error || "unknown error"}`));
        return;
      }
      if (msg.type === eventType) {
        cleanup();
        resolve(msg);
      }
    };

    const onError = (err: Error) => {
      cleanup();
      reject(new Error(`Worker emitted error waiting for "${eventType}" in stage "${stage}": ${err?.message || String(err)}`));
    };

    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(new Error(`Worker exited waiting for "${eventType}" in stage "${stage}" with code ${code} and signal ${signal}`));
    };

    const onDisconnect = () => {
      cleanup();
      reject(new Error(`Worker disconnected waiting for "${eventType}" in stage "${stage}"`));
    };

    child.on("message", onMessage);
    child.on("error", onError);
    child.on("exit", onExit);
    child.on("disconnect", onDisconnect);

    timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timeout after ${timeoutMs}ms waiting for "${eventType}" in stage "${stage}"`));
    }, timeoutMs);
  });
}

export async function terminateWorkerGracefully(child: ChildProcess, graceMs = 2000): Promise<void> {
  if (child.exitCode !== null) return;

  try {
    if (child.connected) {
      child.send({ type: "EXIT" }, () => {});
    } else {
      child.kill("SIGTERM");
    }
  } catch {}

  const exited = await new Promise<boolean>((resolve) => {
    if (child.exitCode !== null) return resolve(true);
    const timer = setTimeout(() => resolve(false), graceMs);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });

  if (!exited && child.exitCode === null) {
    try {
      child.kill("SIGKILL");
    } catch {}
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) return resolve();
      const killTimer = setTimeout(resolve, 1000);
      child.once("exit", () => {
        clearTimeout(killTimer);
        resolve();
      });
    });
  }
}
