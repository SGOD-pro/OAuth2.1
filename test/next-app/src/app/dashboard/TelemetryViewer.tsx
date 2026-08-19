'use client';

import React, { useEffect, useState } from 'react';

interface TelemetryData {
  status: string;
  authorizedUser: string;
  tokenPreview: string;
  timestamp: string;
  telemetry: {
    vehicleId: string;
    mode: string;
    engineSpeedRpm: number;
    velocityKmh: number;
    gear: number;
    oilTempCelsius: number;
    coolantTempCelsius: number;
    boostPressureBar: number;
    batteryLevelPct: number;
    differentialLockPct: number;
    lapTimes: Array<{ lap: number; time: string; sector1: string; sector2: string; sector3: string }>;
    cryptographicDiagnostics: {
      protocol: string;
      authMethod: string;
      encryption: string;
      accessControl: string;
    };
  };
}

export function TelemetryViewer() {
  const [data, setData] = useState<TelemetryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTelemetry = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/secure-data');
      if (!res.ok) {
        throw new Error(`Failed with HTTP ${res.status}: ${await res.text()}`);
      }
      const json = await res.json();
      setData(json);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch secure data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  return (
    <div className="bg-[#0f131a] border border-[#21262d] rounded-2xl p-6 relative overflow-hidden shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <span className="font-mono text-[11px] uppercase tracking-widest text-[#1C69D4] font-semibold block">
            Protected Backend Resource
          </span>
          <h2 className="text-xl font-bold text-white mt-0.5">
            Real-Time Vehicle Telemetry Stream
          </h2>
          <p className="font-mono text-xs text-neutral-400 mt-1">
            Endpoint: <code className="text-[#0066B1] bg-[#161b22] px-2 py-0.5 rounded">GET /api/secure-data</code>
          </p>
        </div>

        <button
          onClick={fetchTelemetry}
          disabled={loading}
          className="inline-flex items-center gap-2 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] text-xs font-mono text-white px-3.5 py-2 rounded-xl transition-all cursor-pointer"
        >
          <span>{loading ? 'Refreshing...' : 'Refresh Telemetry'}</span>
        </button>
      </div>

      {error ? (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 font-mono text-xs text-rose-400">
          ⚠️ {error}
        </div>
      ) : loading && !data ? (
        <div className="py-12 text-center font-mono text-xs text-neutral-400 animate-pulse">
          Establishing encrypted telemetry socket session...
        </div>
      ) : data ? (
        <div className="space-y-6">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
              <span className="font-mono text-[10px] uppercase text-neutral-400 block">Velocity</span>
              <div className="text-2xl font-bold text-white mt-1 font-mono">
                {data.telemetry.velocityKmh} <span className="text-xs font-normal text-neutral-400">km/h</span>
              </div>
            </div>

            <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
              <span className="font-mono text-[10px] uppercase text-neutral-400 block">Engine RPM</span>
              <div className="text-2xl font-bold text-[#E22718] mt-1 font-mono">
                {data.telemetry.engineSpeedRpm} <span className="text-xs font-normal text-neutral-400">RPM</span>
              </div>
            </div>

            <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
              <span className="font-mono text-[10px] uppercase text-neutral-400 block">Oil Temp</span>
              <div className="text-2xl font-bold text-amber-400 mt-1 font-mono">
                {data.telemetry.oilTempCelsius}°C
              </div>
            </div>

            <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
              <span className="font-mono text-[10px] uppercase text-neutral-400 block">Boost Pressure</span>
              <div className="text-2xl font-bold text-[#0066B1] mt-1 font-mono">
                {data.telemetry.boostPressureBar} <span className="text-xs font-normal text-neutral-400">bar</span>
              </div>
            </div>
          </div>

          {/* Diagnostics Section */}
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4 font-mono text-xs space-y-2">
            <div className="text-neutral-400 font-semibold border-b border-[#21262d] pb-2 mb-2">
              Cryptographic Token Validation Status
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-neutral-400">Security Protocol: </span>
                <span className="text-neutral-200">{data.telemetry.cryptographicDiagnostics.protocol}</span>
              </div>
              <div>
                <span className="text-neutral-400">Auth Method: </span>
                <span className="text-neutral-200">{data.telemetry.cryptographicDiagnostics.authMethod}</span>
              </div>
              <div>
                <span className="text-neutral-400">Active Token Preview: </span>
                <span className="text-emerald-400 font-bold">{data.tokenPreview}</span>
              </div>
              <div>
                <span className="text-neutral-400">Stream Timestamp: </span>
                <span className="text-neutral-200">{new Date(data.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
